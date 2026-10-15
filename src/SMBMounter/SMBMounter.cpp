/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * SMBMounter - a small native application to mount and unmount SMB shares,
 * with a list of favorite connections. It also works as a Tracker add-on (it
 * launches itself when selected from Tracker's add-ons menu).
 */


#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <Alert.h>
#include <Application.h>
#include <Button.h>
#include <Catalog.h>
#include <CheckBox.h>
#include <Directory.h>
#include <Entry.h>
#include <File.h>
#include <FindDirectory.h>
#include <Invoker.h>
#include <Key.h>
#include <KeyStore.h>
#include <LayoutBuilder.h>
#include <ListView.h>
#include <MenuItem.h>
#include <Message.h>
#include <Messenger.h>
#include <NodeMonitor.h>
#include <Path.h>
#include <PopUpMenu.h>
#include <Roster.h>
#include <ScrollView.h>
#include <SeparatorView.h>
#include <String.h>
#include <StringItem.h>
#include <StringView.h>
#include <TextControl.h>
#include <Volume.h>
#include <VolumeRoster.h>
#include <Window.h>
#include <fs_info.h>
#include <fs_volume.h>

#include <TrackerAddOnAppLaunch.h>


static const char* kApplicationSignature
	= "application/x-vnd.HaikuSMB-SMBMounter";
static const char* kSettingsFileName = "SMBMounter settings";

enum {
	kMsgMount			= 'mnt ',
	kMsgUnmount			= 'umnt',
	kMsgShareChanged	= 'shch',
	kMsgSelectionChanged = 'selc',
	kMsgRefresh			= 'rfsh',

	// favorites
	kMsgFavoriteSelected = 'fsel',
	kMsgFavoriteInvoked	= 'finv',
	kMsgAddFavorite		= 'addf',
	kMsgFavoriteNamed	= 'fnam',
	kMsgRenameFavorite	= 'renf',
	kMsgFavoriteRenamed	= 'frnm',
	kMsgRemoveFavorite	= 'remf',
	kMsgRemoveConfirmed	= 'remc',

	// name prompt
	kMsgNameChanged		= 'nmch',
	kMsgNameAccepted	= 'nmok'
};



// Mount point policy (shared with SMBMounter): never mount over system
// directories or non-empty directories. Like Haiku's disk mounter, the default
// mount point is /<share>, with a number appended if that is taken.
static const char* const kReservedMountPoints[] = {
	"/", "/boot", "/dev", "/bin", "/etc", "/packages", "/system", "/tmp",
	"/var", "/trash", NULL
};


static bool
is_reserved_mount_point(const char* path)
{
	BString normalized(path);
	while (normalized.Length() > 1 && normalized.EndsWith("/"))
		normalized.Truncate(normalized.Length() - 1);
	for (int i = 0; kReservedMountPoints[i] != NULL; i++) {
		if (normalized == kReservedMountPoints[i])
			return true;
	}
	return false;
}


// Returns B_OK if the path can be used as a mount point (it either does not
// exist, or is an empty directory); *_exists tells whether it exists.
static status_t
check_mount_point(const char* path, bool* _exists)
{
	if (is_reserved_mount_point(path))
		return B_NOT_ALLOWED;
	struct stat st;
	if (lstat(path, &st) != 0) {
		*_exists = false;
		return B_OK;
	}
	*_exists = true;
	if (!S_ISDIR(st.st_mode))
		return B_NOT_A_DIRECTORY;
	DIR* dir = opendir(path);
	if (dir == NULL)
		return errno;
	bool empty = true;
	while (struct dirent* entry = readdir(dir)) {
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
			empty = false;
			break;
		}
	}
	closedir(dir);
	return empty ? B_OK : B_DIRECTORY_NOT_EMPTY;
}


static BString
default_mount_point(const char* share)
{
	BString name(share);
	name.ReplaceAll('/', '-');
	name.ReplaceAll('\\', '-');
	name.Trim();
	if (name.Length() == 0)
		name = "smb";
	for (int32 i = 1; i < 1000; i++) {
		BString path("/");
		path << name;
		if (i > 1)
			path << (i - 1);
		bool exists;
		if (check_mount_point(path.String(), &exists) == B_OK)
			return path;
	}
	BString path("/");
	path << name;
	return path;
}


static BString
quote_value(const char* value)
{
	BString result;
	if (strpbrk(value, " \t\"'") == NULL) {
		result = value;
		return result;
	}
	result << '"';
	for (const char* p = value; *p != '\0'; p++) {
		if (*p == '"' || *p == '\\')
			result << '\\';
		result << *p;
	}
	result << '"';
	return result;
}


// #pragma mark - MountedItem


class MountedItem : public BStringItem {
public:
	MountedItem(const char* label, dev_t device, const char* path)
		:
		BStringItem(label),
		fDevice(device),
		fPath(path)
	{
	}

	dev_t Device() const { return fDevice; }
	const char* Path() const { return fPath.String(); }

private:
	dev_t	fDevice;
	BString	fPath;
};


// Custom messages may arrive through scripting ("hey SMBMounter addf of
// Window 0"); hey waits for a reply, so send an empty one.
static void
reply_if_scripted(BMessage* message)
{
	if (message->IsSourceWaiting()) {
		BMessage reply(B_REPLY);
		message->SendReply(&reply);
	}
}


// #pragma mark - Favorites


// A saved connection. Passwords are never stored in a favorite: when
// "remember" is set, the password lives in the system key store under the
// same identifier the plain "Remember password" option uses.
struct Favorite {
	BString	name;
	BString	server;
	BString	share;
	BString	user;
	BString	domain;
	BString	mountPoint;
	bool	sign;
	bool	seal;
	bool	readOnly;
	bool	remember;

	Favorite()
		:
		sign(false),
		seal(false),
		readOnly(false),
		remember(false)
	{
	}

	void Archive(BMessage& into) const
	{
		into.MakeEmpty();
		into.AddString("name", name);
		into.AddString("server", server);
		into.AddString("share", share);
		into.AddString("user", user);
		into.AddString("domain", domain);
		into.AddString("mountpoint", mountPoint);
		into.AddBool("sign", sign);
		into.AddBool("seal", seal);
		into.AddBool("readonly", readOnly);
		into.AddBool("remember", remember);
	}

	status_t Unarchive(const BMessage& from)
	{
		if (from.FindString("name", &name) != B_OK
			|| from.FindString("server", &server) != B_OK
			|| from.FindString("share", &share) != B_OK) {
			return B_BAD_VALUE;
		}
		from.FindString("user", &user);
		from.FindString("domain", &domain);
		from.FindString("mountpoint", &mountPoint);
		from.FindBool("sign", &sign);
		from.FindBool("seal", &seal);
		from.FindBool("readonly", &readOnly);
		from.FindBool("remember", &remember);
		return B_OK;
	}
};


class FavoriteItem : public BStringItem {
public:
	FavoriteItem(const Favorite& favorite)
		:
		BStringItem(favorite.name.String()),
		fFavorite(favorite)
	{
	}

	const Favorite& Data() const { return fFavorite; }
	Favorite& Data() { return fFavorite; }

	void SetName(const char* name)
	{
		fFavorite.name = name;
		SetText(name);
	}

private:
	Favorite	fFavorite;
};


// The favorites list: a right click opens a context menu, the Delete key
// removes the selected favorite. Selection and invocation (double click)
// messages go to the window.
class FavoritesListView : public BListView {
public:
	FavoritesListView(const char* name)
		:
		BListView(name, B_SINGLE_SELECTION_LIST)
	{
	}

	virtual void MouseDown(BPoint where)
	{
		int32 buttons = 0;
		if (Window() != NULL && Window()->CurrentMessage() != NULL)
			Window()->CurrentMessage()->FindInt32("buttons", &buttons);
		if ((buttons & B_SECONDARY_MOUSE_BUTTON) == 0) {
			BListView::MouseDown(where);
			return;
		}
		int32 index = IndexOf(where);
		if (index < 0)
			return;
		Select(index);

		BPopUpMenu* menu = new BPopUpMenu("favorite", false, false);
		menu->AddItem(new BMenuItem("Mount",
			new BMessage(kMsgFavoriteInvoked)));
		menu->AddItem(new BMenuItem("Rename" B_UTF8_ELLIPSIS,
			new BMessage(kMsgRenameFavorite)));
		menu->AddSeparatorItem();
		menu->AddItem(new BMenuItem("Remove",
			new BMessage(kMsgRemoveFavorite)));
		menu->SetTargetForItems(Window());
		menu->SetAsyncAutoDestruct(true);
		menu->Go(ConvertToScreen(where), true, true, true);
	}

	virtual void KeyDown(const char* bytes, int32 numBytes)
	{
		if (numBytes == 1 && (bytes[0] == B_DELETE || bytes[0] == B_BACKSPACE)
			&& CurrentSelection() >= 0 && Window() != NULL) {
			Window()->PostMessage(kMsgRemoveFavorite);
			return;
		}
		BListView::KeyDown(bytes, numBytes);
	}
};


// A small dialog asking for a favorite's name. It is modal for its parent
// window only; the answer is sent to the parent as a copy of the template
// message with a "name" string added.
class NamePromptWindow : public BWindow {
public:
	NamePromptWindow(BWindow* parent, const char* title,
		const char* initialName, const BMessage& templateMessage)
		:
		BWindow(BRect(0, 0, 320, 90), title, B_FLOATING_WINDOW_LOOK,
			B_MODAL_SUBSET_WINDOW_FEEL,
			B_NOT_RESIZABLE | B_NOT_ZOOMABLE | B_AUTO_UPDATE_SIZE_LIMITS
				| B_CLOSE_ON_ESCAPE),
		fTarget(parent),
		fTemplate(templateMessage)
	{
		AddToSubset(parent);

		fName = new BTextControl("name", "Name:", initialName, NULL);
		fName->SetModificationMessage(new BMessage(kMsgNameChanged));
		fName->SetExplicitMinSize(BSize(280, B_SIZE_UNSET));
		fOkButton = new BButton("ok", "OK", new BMessage(kMsgNameAccepted));
		fOkButton->MakeDefault(true);
		fOkButton->SetEnabled(initialName != NULL && initialName[0] != '\0');
		BButton* cancel = new BButton("cancel", "Cancel",
			new BMessage(B_QUIT_REQUESTED));

		BLayoutBuilder::Group<>(this, B_VERTICAL, B_USE_DEFAULT_SPACING)
			.SetInsets(B_USE_WINDOW_INSETS)
			.Add(fName)
			.AddGroup(B_HORIZONTAL)
				.AddGlue()
				.Add(cancel)
				.Add(fOkButton)
			.End();

		fName->MakeFocus(true);
		fName->TextView()->SelectAll();
		CenterIn(parent->Frame());
	}

	virtual void MessageReceived(BMessage* message)
	{
		switch (message->what) {
			case kMsgNameChanged:
			{
				BString name(fName->Text());
				name.Trim();
				fOkButton->SetEnabled(name.Length() > 0);
				break;
			}
			case kMsgNameAccepted:
			{
				reply_if_scripted(message);
				BString name(fName->Text());
				name.Trim();
				if (name.Length() == 0)
					break;
				BMessage result(fTemplate);
				result.AddString("name", name);
				fTarget.SendMessage(&result);
				PostMessage(B_QUIT_REQUESTED);
				break;
			}
			default:
				BWindow::MessageReceived(message);
		}
	}

private:
	BMessenger		fTarget;
	BMessage		fTemplate;
	BTextControl*	fName;
	BButton*		fOkButton;
};


// #pragma mark - MounterWindow


class MounterWindow : public BWindow {
public:
								MounterWindow();
	virtual						~MounterWindow();

	virtual	void				MessageReceived(BMessage* message);
	virtual	bool				QuitRequested();

			void				SetShare(const char* server, const char* share);
			void				SetField(const char* key, const char* value);

private:
			void				_LoadSettings();
			void				_SaveSettings();
			void				_UpdateMountPoint();
			void				_Mount();
			void				_Unmount();
			void				_RefreshMountedList();
			void				_LoadPassword();
			void				_StorePassword();
			BString				_KeyIdentifier() const;
			void				_ShowError(const char* title, const char* text);

			void				_LoadFavorites(const BMessage& settings);
			void				_SaveFavorites(BMessage& settings) const;
			FavoriteItem*		_SelectedFavorite() const;
			int32				_FindFavorite(const char* name) const;
			void				_CurrentFavorite(Favorite& favorite) const;
			BString				_DefaultFavoriteName() const;
			void				_ApplyFavorite(const Favorite& favorite);
			void				_AddFavorite(const char* name);
			void				_PromptForName(const char* title,
									const char* initialName,
									const BMessage& result);

private:
			FavoritesListView*	fFavoritesList;
			BButton*			fAddFavoriteButton;
			BButton*			fRemoveFavoriteButton;
			BTextControl*		fServer;
			BTextControl*		fShare;
			BTextControl*		fUser;
			BTextControl*		fPassword;
			BTextControl*		fDomain;
			BTextControl*		fMountPoint;
			BCheckBox*			fRemember;
			BCheckBox*			fSign;
			BCheckBox*			fSeal;
			BCheckBox*			fReadOnly;
			BButton*			fMountButton;
			BListView*			fMountedList;
			BButton*			fUnmountButton;
			BStringView*		fStatus;
			bool				fMountPointEdited;
			BString				fMountPointShare;
			bool				fPasswordFromKeyStore;
};


MounterWindow::MounterWindow()
	:
	BWindow(BRect(100, 100, 720, 520), "SMBMounter", B_TITLED_WINDOW,
		B_NOT_ZOOMABLE | B_AUTO_UPDATE_SIZE_LIMITS | B_QUIT_ON_WINDOW_CLOSE),
	fMountPointEdited(false),
	fPasswordFromKeyStore(false)
{
	fServer = new BTextControl("server", "Server:", "", NULL);
	fShare = new BTextControl("share", "Share:", "",
		new BMessage(kMsgShareChanged));
	fShare->SetModificationMessage(new BMessage(kMsgShareChanged));
	fUser = new BTextControl("user", "User name:", "", NULL);
	fPassword = new BTextControl("password", "Password:", "", NULL);
	fPassword->TextView()->HideTyping(true);
	fDomain = new BTextControl("domain", "Domain:", "", NULL);
	fMountPoint = new BTextControl("mountpoint", "Mount at:", "", NULL);
	fRemember = new BCheckBox("remember", "Remember password", NULL);
	fSign = new BCheckBox("sign", "Require signing", NULL);
	fSeal = new BCheckBox("seal", "Encrypt traffic", NULL);
	fReadOnly = new BCheckBox("readonly", "Read-only", NULL);
	fMountButton = new BButton("mount", "Mount", new BMessage(kMsgMount));
	fMountButton->MakeDefault(true);

	fMountedList = new BListView("mounted");
	fMountedList->SetSelectionMessage(new BMessage(kMsgSelectionChanged));
	fMountedList->SetExplicitMinSize(BSize(B_SIZE_UNSET, 80));
	BScrollView* scrollView = new BScrollView("scroll", fMountedList, 0,
		false, true);
	fUnmountButton = new BButton("unmount", "Unmount",
		new BMessage(kMsgUnmount));
	fUnmountButton->SetEnabled(false);
	fStatus = new BStringView("status", "");

	// Favorites side panel
	fFavoritesList = new FavoritesListView("favorites");
	fFavoritesList->SetSelectionMessage(new BMessage(kMsgFavoriteSelected));
	fFavoritesList->SetInvocationMessage(new BMessage(kMsgFavoriteInvoked));
	BScrollView* favoritesScroll = new BScrollView("favoritesScroll",
		fFavoritesList, 0, false, true);
	favoritesScroll->SetExplicitMinSize(BSize(180, 160));
	favoritesScroll->SetExplicitMaxSize(BSize(300, B_SIZE_UNSET));
	fAddFavoriteButton = new BButton("addFavorite", "Add" B_UTF8_ELLIPSIS,
		new BMessage(kMsgAddFavorite));
	fAddFavoriteButton->SetToolTip("Save the connection entered on the right "
		"as a favorite");
	fRemoveFavoriteButton = new BButton("removeFavorite", "Remove",
		new BMessage(kMsgRemoveFavorite));
	fRemoveFavoriteButton->SetEnabled(false);

	BLayoutBuilder::Group<>(this, B_HORIZONTAL, B_USE_DEFAULT_SPACING)
		.SetInsets(B_USE_WINDOW_INSETS)
		.AddGroup(B_VERTICAL, B_USE_SMALL_SPACING, 0.3f)
			.Add(new BStringView("favoritesLabel", "Favorites:"))
			.Add(favoritesScroll)
			.AddGroup(B_HORIZONTAL, B_USE_SMALL_SPACING)
				.Add(fAddFavoriteButton)
				.Add(fRemoveFavoriteButton)
			.End()
		.End()
		.Add(new BSeparatorView(B_VERTICAL))
		.AddGroup(B_VERTICAL, B_USE_DEFAULT_SPACING, 1.0f)
			.AddGrid(B_USE_DEFAULT_SPACING, B_USE_SMALL_SPACING)
				.Add(fServer->CreateLabelLayoutItem(), 0, 0)
				.Add(fServer->CreateTextViewLayoutItem(), 1, 0, 2)
				.Add(fShare->CreateLabelLayoutItem(), 0, 1)
				.Add(fShare->CreateTextViewLayoutItem(), 1, 1, 2)
				.Add(fUser->CreateLabelLayoutItem(), 0, 2)
				.Add(fUser->CreateTextViewLayoutItem(), 1, 2, 2)
				.Add(fPassword->CreateLabelLayoutItem(), 0, 3)
				.Add(fPassword->CreateTextViewLayoutItem(), 1, 3)
				.Add(fRemember, 2, 3)
				.Add(fDomain->CreateLabelLayoutItem(), 0, 4)
				.Add(fDomain->CreateTextViewLayoutItem(), 1, 4, 2)
				.Add(fMountPoint->CreateLabelLayoutItem(), 0, 5)
				.Add(fMountPoint->CreateTextViewLayoutItem(), 1, 5, 2)
			.End()
			.AddGroup(B_HORIZONTAL)
				.Add(fSign)
				.Add(fSeal)
				.Add(fReadOnly)
				.AddGlue()
				.Add(fMountButton)
			.End()
			.Add(new BSeparatorView(B_HORIZONTAL))
			.Add(new BStringView("label", "Mounted SMB shares:"))
			.Add(scrollView)
			.AddGroup(B_HORIZONTAL)
				.Add(fStatus)
				.AddGlue()
				.Add(fUnmountButton)
			.End()
		.End();

	_LoadSettings();
	_UpdateMountPoint();
	_RefreshMountedList();
	fServer->MakeFocus(true);

	watch_node(NULL, B_WATCH_MOUNT, this);
	CenterOnScreen();
}


MounterWindow::~MounterWindow()
{
	stop_watching(this);
}


bool
MounterWindow::QuitRequested()
{
	_SaveSettings();
	return BWindow::QuitRequested();
}


void
MounterWindow::SetShare(const char* server, const char* share)
{
	if (server != NULL)
		fServer->SetText(server);
	if (share != NULL)
		fShare->SetText(share);
	fMountPointEdited = false;
	_UpdateMountPoint();
	_LoadPassword();
}


void
MounterWindow::SetField(const char* key, const char* value)
{
	if (strcmp(key, "user") == 0)
		fUser->SetText(value);
	else if (strcmp(key, "password") == 0)
		fPassword->SetText(value);
	else if (strcmp(key, "domain") == 0)
		fDomain->SetText(value);
	else if (strcmp(key, "mountpoint") == 0) {
		fMountPoint->SetText(value);
		fMountPointEdited = value[0] != '\0';
	} else if (strcmp(key, "sign") == 0)
		fSign->SetValue(B_CONTROL_ON);
	else if (strcmp(key, "seal") == 0)
		fSeal->SetValue(B_CONTROL_ON);
	else if (strcmp(key, "ro") == 0)
		fReadOnly->SetValue(B_CONTROL_ON);
}


void
MounterWindow::MessageReceived(BMessage* message)
{
	// Our own messages may be sent via scripting ("hey SMBMounter finv of
	// Window 0"); reply once the action is done so that scripts can
	// continue.
	bool custom = false;
	switch (message->what) {
		case kMsgMount:
		case kMsgUnmount:
		case kMsgRefresh:
		case kMsgAddFavorite:
		case kMsgRenameFavorite:
		case kMsgRemoveFavorite:
		case kMsgRemoveConfirmed:
		case kMsgFavoriteInvoked:
			custom = true;
			break;
		default:
			break;
	}

	switch (message->what) {
		case kMsgMount:
			_Mount();
			break;
		case kMsgUnmount:
			_Unmount();
			break;
		case kMsgShareChanged:
			// Setting the share text programmatically also posts this
			// message; only recompute when the share really changed, so
			// that the default is not recomputed right after a mount.
			if (fMountPointShare != fShare->Text())
				_UpdateMountPoint();
			break;
		case kMsgSelectionChanged:
			fUnmountButton->SetEnabled(fMountedList->CurrentSelection() >= 0);
			break;
		case kMsgRefresh:
			_RefreshMountedList();
			break;

		case kMsgFavoriteSelected:
		{
			FavoriteItem* item = _SelectedFavorite();
			fRemoveFavoriteButton->SetEnabled(item != NULL);
			if (item != NULL)
				_ApplyFavorite(item->Data());
			break;
		}
		case kMsgFavoriteInvoked:
		{
			FavoriteItem* item = _SelectedFavorite();
			if (item != NULL) {
				_ApplyFavorite(item->Data());
				_Mount();
			}
			break;
		}
		case kMsgAddFavorite:
		{
			BString server(fServer->Text());
			BString share(fShare->Text());
			server.Trim();
			share.Trim();
			if (server.Length() == 0 || share.Length() == 0) {
				_ShowError("SMBMounter", "Enter at least a server and a share "
					"name first. A favorite saves the values currently in the "
					"form (the password only if \"Remember password\" is "
					"checked, and then in the key store).");
				break;
			}
			BMessage result(kMsgFavoriteNamed);
			_PromptForName("Add favorite", _DefaultFavoriteName().String(),
				result);
			break;
		}
		case kMsgFavoriteNamed:
		{
			const char* name;
			if (message->FindString("name", &name) == B_OK)
				_AddFavorite(name);
			break;
		}
		case kMsgRenameFavorite:
		{
			FavoriteItem* item = _SelectedFavorite();
			if (item == NULL)
				break;
			BMessage result(kMsgFavoriteRenamed);
			result.AddInt32("index", fFavoritesList->CurrentSelection());
			_PromptForName("Rename favorite", item->Data().name.String(),
				result);
			break;
		}
		case kMsgFavoriteRenamed:
		{
			const char* name;
			int32 index;
			if (message->FindString("name", &name) != B_OK
				|| message->FindInt32("index", &index) != B_OK) {
				break;
			}
			FavoriteItem* item = dynamic_cast<FavoriteItem*>(
				fFavoritesList->ItemAt(index));
			if (item == NULL)
				break;
			int32 existing = _FindFavorite(name);
			if (existing >= 0 && existing != index) {
				BString text("A favorite named \"");
				text << name << "\" already exists.";
				_ShowError("SMBMounter", text.String());
				break;
			}
			item->SetName(name);
			fFavoritesList->InvalidateItem(index);
			_SaveSettings();
			break;
		}
		case kMsgRemoveFavorite:
		{
			FavoriteItem* item = _SelectedFavorite();
			if (item == NULL)
				break;
			BString text("Remove the favorite \"");
			text << item->Data().name << "\"?";
			BAlert* alert = new BAlert("SMBMounter", text.String(), "Cancel",
				"Remove", NULL, B_WIDTH_AS_USUAL, B_WARNING_ALERT);
			alert->SetShortcut(0, B_ESCAPE);
			BMessage* reply = new BMessage(kMsgRemoveConfirmed);
			reply->AddInt32("index", fFavoritesList->CurrentSelection());
			reply->AddString("name", item->Data().name);
			alert->Go(new BInvoker(reply, this));
			break;
		}
		case kMsgRemoveConfirmed:
		{
			int32 which;
			int32 index;
			const char* name;
			if (message->FindInt32("which", &which) != B_OK || which != 1
				|| message->FindInt32("index", &index) != B_OK
				|| message->FindString("name", &name) != B_OK) {
				break;
			}
			FavoriteItem* item = dynamic_cast<FavoriteItem*>(
				fFavoritesList->ItemAt(index));
			if (item == NULL || item->Data().name != name)
				break;
			fFavoritesList->RemoveItem(item);
			delete item;
			fRemoveFavoriteButton->SetEnabled(
				fFavoritesList->CurrentSelection() >= 0);
			_SaveSettings();
			break;
		}

		case B_NODE_MONITOR:
		{
			int32 opcode;
			if (message->FindInt32("opcode", &opcode) == B_OK
				&& (opcode == B_DEVICE_MOUNTED
					|| opcode == B_DEVICE_UNMOUNTED)) {
				_RefreshMountedList();
			}
			break;
		}
		default:
			BWindow::MessageReceived(message);
	}

	if (custom)
		reply_if_scripted(message);
}


void
MounterWindow::_UpdateMountPoint()
{
	fMountPointShare = fShare->Text();
	if (fMountPointEdited)
		return;
	BString mountPoint;
	if (fShare->Text()[0] != '\0')
		mountPoint = default_mount_point(fShare->Text());
	fMountPoint->SetText(mountPoint.String());
}


BString
MounterWindow::_KeyIdentifier() const
{
	BString identifier("smb://");
	identifier << fServer->Text() << "/" << fShare->Text();
	return identifier;
}


void
MounterWindow::_LoadPassword()
{
	// Only touch the key store when the user asked us to remember the
	// password (the key store asks for permission on first use).
	if (fRemember->Value() != B_CONTROL_ON || fPassword->Text()[0] != '\0')
		return;
	if (fServer->Text()[0] == '\0' || fShare->Text()[0] == '\0')
		return;
	BKeyStore keyStore;
	BPasswordKey key;
	BString identifier = _KeyIdentifier();
	if (keyStore.GetKey(B_KEY_TYPE_PASSWORD, identifier.String(),
			fUser->Text(), true, key) == B_OK) {
		fPassword->SetText(key.Password());
		fPasswordFromKeyStore = true;
	}
}


void
MounterWindow::_StorePassword()
{
	bool remember = fRemember->Value() == B_CONTROL_ON;
	if (!remember && !fPasswordFromKeyStore)
		return;

	BKeyStore keyStore;
	BString identifier = _KeyIdentifier();
	BPasswordKey oldKey;
	if (keyStore.GetKey(B_KEY_TYPE_PASSWORD, identifier.String(),
			fUser->Text(), true, oldKey) == B_OK) {
		if (!remember || strcmp(oldKey.Password(), fPassword->Text()) != 0)
			keyStore.RemoveKey(oldKey);
		else
			return;
	}
	if (remember) {
		BPasswordKey key(fPassword->Text(), B_KEY_PURPOSE_NETWORK,
			identifier.String(), fUser->Text());
		keyStore.AddKey(key);
		fPasswordFromKeyStore = true;
	} else
		fPasswordFromKeyStore = false;
}


void
MounterWindow::_ShowError(const char* title, const char* text)
{
	BAlert* alert = new BAlert(title, text, "OK", NULL, NULL,
		B_WIDTH_AS_USUAL, B_STOP_ALERT);
	alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
	// asynchronous, so the window keeps processing messages
	alert->Go(NULL);
}


void
MounterWindow::_Mount()
{
	BString server(fServer->Text());
	BString share(fShare->Text());
	server.Trim();
	share.Trim();
	// accept //server/share typed into the server field
	if (share.Length() == 0 && (server.StartsWith("//")
			|| server.StartsWith("\\\\"))) {
		BString unc(server);
		unc.ReplaceAll('\\', '/');
		unc.RemoveFirst("//");
		int32 slash = unc.FindFirst('/');
		if (slash > 0) {
			server = unc;
			server.Truncate(slash);
			share = unc.String() + slash + 1;
			fServer->SetText(server.String());
			fShare->SetText(share.String());
			fMountPointEdited = false;
			_UpdateMountPoint();
		}
	}
	if (server.Length() == 0 || share.Length() == 0) {
		_ShowError("SMBMounter", "Please enter both a server and a share "
			"name.");
		return;
	}

	BString mountPoint(fMountPoint->Text());
	mountPoint.Trim();
	if (mountPoint.Length() == 0 || mountPoint == "/")
		mountPoint = default_mount_point(share.String());

	BString parameters;
	parameters << "//" << server << "/" << share;
	if (fUser->Text()[0] != '\0')
		parameters << " user=" << quote_value(fUser->Text());
	if (fPassword->Text()[0] != '\0')
		parameters << " password=" << quote_value(fPassword->Text());
	if (fDomain->Text()[0] != '\0')
		parameters << " domain=" << quote_value(fDomain->Text());
	if (fSign->Value() == B_CONTROL_ON)
		parameters << " sign";
	if (fSeal->Value() == B_CONTROL_ON)
		parameters << " seal";

	bool exists = false;
	status_t check = check_mount_point(mountPoint.String(), &exists);
	if (check != B_OK) {
		BString text("The mount point \"");
		text << mountPoint << "\" cannot be used: ";
		if (check == B_NOT_ALLOWED)
			text << "it is a system directory.";
		else if (check == B_DIRECTORY_NOT_EMPTY)
			text << "the directory is not empty.";
		else if (check == B_NOT_A_DIRECTORY)
			text << "it is not a directory.";
		else
			text << strerror(check);
		text << "\n\nMount points must be empty directories, for example "
			<< default_mount_point(share.String()) << ".";
		_ShowError("SMBMounter", text.String());
		return;
	}
	bool createdMountPoint = false;
	if (!exists) {
		if (create_directory(mountPoint.String(), 0755) != B_OK) {
			BString text("The mount point \"");
			text << mountPoint << "\" could not be created: "
				<< strerror(errno);
			_ShowError("SMBMounter", text.String());
			return;
		}
		createdMountPoint = true;
	}

	fStatus->SetText("Connecting" B_UTF8_ELLIPSIS);
	fMountButton->SetEnabled(false);
	UpdateIfNeeded();

	dev_t device = fs_mount_volume(mountPoint.String(), NULL, "smbfs",
		fReadOnly->Value() == B_CONTROL_ON ? B_MOUNT_READ_ONLY : 0,
		parameters.String());

	fMountButton->SetEnabled(true);
	if (device < 0) {
		if (createdMountPoint)
			rmdir(mountPoint.String());
		fStatus->SetText("");
		BString text("Mounting //");
		text << server << "/" << share << " failed:\n\n" << strerror(device);
		if (device == B_PERMISSION_DENIED) {
			text << "\n\nCheck the user name, password and domain.";
		} else if (device == B_ENTRY_NOT_FOUND) {
			text << "\n\nThe share does not exist on the server.";
		} else if (device == B_NAME_NOT_FOUND) {
			text << "\n\nThe server name could not be resolved.";
		}
		_ShowError("SMBMounter", text.String());
		return;
	}

	_StorePassword();
	_SaveSettings();
	BString status("Mounted at ");
	status << mountPoint;
	fStatus->SetText(status.String());
	_RefreshMountedList();

	// Open the new volume in Tracker.
	entry_ref ref;
	if (get_ref_for_path(mountPoint.String(), &ref) == B_OK)
		be_roster->Launch(&ref);
}


void
MounterWindow::_Unmount()
{
	int32 index = fMountedList->CurrentSelection();
	if (index < 0 && fMountedList->CountItems() == 1)
		index = 0;
	if (index < 0)
		return;
	MountedItem* item = dynamic_cast<MountedItem*>(
		fMountedList->ItemAt(index));
	if (item == NULL)
		return;

	BString path(item->Path());
	// Right after mounting, Tracker and other daemons may still be looking
	// at the volume; retry a few times before reporting it as busy.
	status_t status = B_BUSY;
	for (int attempt = 0; attempt < 5 && status == B_BUSY; attempt++) {
		if (attempt > 0)
			snooze(300000);
		status = fs_unmount_volume(path.String(), 0);
	}
	if (status != B_OK) {
		BString text("Unmounting \"");
		text << path << "\" failed:\n\n" << strerror(status);
		if (status == B_BUSY) {
			text << "\n\nFiles on the share are still in use. Close them "
				"and try again.";
		}
		_ShowError("SMBMounter", text.String());
		return;
	}
	// Remove the (now empty) mount point directory.
	rmdir(path.String());
	fStatus->SetText("Unmounted");
	_RefreshMountedList();
}


void
MounterWindow::_RefreshMountedList()
{
	int32 selected = fMountedList->CurrentSelection();
	BString selectedPath;
	if (selected >= 0) {
		MountedItem* item = dynamic_cast<MountedItem*>(
			fMountedList->ItemAt(selected));
		if (item != NULL)
			selectedPath = item->Path();
	}

	while (BListItem* item = fMountedList->RemoveItem((int32)0))
		delete item;

	BVolumeRoster roster;
	BVolume volume;
	while (roster.GetNextVolume(&volume) == B_OK) {
		fs_info info;
		if (fs_stat_dev(volume.Device(), &info) != B_OK)
			continue;
		if (strcmp(info.fsh_name, "smbfs") != 0)
			continue;
		BDirectory root;
		BEntry entry;
		BPath path;
		if (volume.GetRootDirectory(&root) != B_OK
			|| root.GetEntry(&entry) != B_OK
			|| entry.GetPath(&path) != B_OK) {
			continue;
		}
		BString label(info.device_name);
		label << "  \xe2\x86\x92  " << path.Path();
		if ((info.flags & B_FS_IS_READONLY) != 0)
			label << "  (read-only)";
		MountedItem* item = new MountedItem(label.String(), volume.Device(),
			path.Path());
		fMountedList->AddItem(item);
		if (selectedPath == path.Path())
			fMountedList->Select(fMountedList->CountItems() - 1);
	}
	fUnmountButton->SetEnabled(fMountedList->CurrentSelection() >= 0);
}


// #pragma mark - favorites


void
MounterWindow::_LoadFavorites(const BMessage& settings)
{
	BMessage archive;
	for (int32 i = 0; settings.FindMessage("favorite", i, &archive) == B_OK;
			i++) {
		Favorite favorite;
		if (favorite.Unarchive(archive) == B_OK)
			fFavoritesList->AddItem(new FavoriteItem(favorite));
	}
}


void
MounterWindow::_SaveFavorites(BMessage& settings) const
{
	for (int32 i = 0; i < fFavoritesList->CountItems(); i++) {
		FavoriteItem* item = dynamic_cast<FavoriteItem*>(
			fFavoritesList->ItemAt(i));
		if (item == NULL)
			continue;
		BMessage archive;
		item->Data().Archive(archive);
		settings.AddMessage("favorite", &archive);
	}
}


FavoriteItem*
MounterWindow::_SelectedFavorite() const
{
	int32 index = fFavoritesList->CurrentSelection();
	if (index < 0)
		return NULL;
	return dynamic_cast<FavoriteItem*>(fFavoritesList->ItemAt(index));
}


int32
MounterWindow::_FindFavorite(const char* name) const
{
	for (int32 i = 0; i < fFavoritesList->CountItems(); i++) {
		FavoriteItem* item = dynamic_cast<FavoriteItem*>(
			fFavoritesList->ItemAt(i));
		if (item != NULL && item->Data().name == name)
			return i;
	}
	return -1;
}


// Fills in a favorite from the current contents of the form.
void
MounterWindow::_CurrentFavorite(Favorite& favorite) const
{
	favorite.server = fServer->Text();
	favorite.share = fShare->Text();
	favorite.server.Trim();
	favorite.share.Trim();
	favorite.user = fUser->Text();
	favorite.domain = fDomain->Text();
	// Only keep a mount point that differs from the default, so that the
	// favorite keeps following the /<share> rule otherwise.
	BString defaultMountPoint("/");
	defaultMountPoint << favorite.share;
	favorite.mountPoint = fMountPoint->Text();
	favorite.mountPoint.Trim();
	if (favorite.mountPoint == defaultMountPoint)
		favorite.mountPoint = "";
	favorite.sign = fSign->Value() == B_CONTROL_ON;
	favorite.seal = fSeal->Value() == B_CONTROL_ON;
	favorite.readOnly = fReadOnly->Value() == B_CONTROL_ON;
	favorite.remember = fRemember->Value() == B_CONTROL_ON;
}


BString
MounterWindow::_DefaultFavoriteName() const
{
	BString server(fServer->Text());
	BString share(fShare->Text());
	server.Trim();
	share.Trim();
	BString name(share);
	name << " on " << server;
	return name;
}


// Puts a favorite's values into the form. The password is fetched from the
// key store when the favorite was saved with "Remember password".
void
MounterWindow::_ApplyFavorite(const Favorite& favorite)
{
	bool sameAccount = favorite.server == fServer->Text()
		&& favorite.share == fShare->Text() && favorite.user == fUser->Text();

	fServer->SetText(favorite.server.String());
	fShare->SetText(favorite.share.String());
	fUser->SetText(favorite.user.String());
	fDomain->SetText(favorite.domain.String());
	if (!sameAccount) {
		fPassword->SetText("");
		fPasswordFromKeyStore = false;
	}
	fSign->SetValue(favorite.sign ? B_CONTROL_ON : B_CONTROL_OFF);
	fSeal->SetValue(favorite.seal ? B_CONTROL_ON : B_CONTROL_OFF);
	fReadOnly->SetValue(favorite.readOnly ? B_CONTROL_ON : B_CONTROL_OFF);
	fRemember->SetValue(favorite.remember ? B_CONTROL_ON : B_CONTROL_OFF);
	if (favorite.mountPoint.Length() > 0) {
		fMountPoint->SetText(favorite.mountPoint.String());
		fMountPointEdited = true;
	} else {
		fMountPointEdited = false;
		_UpdateMountPoint();
	}
	_LoadPassword();

	BString status("Favorite \"");
	status << favorite.name << "\"";
	fStatus->SetText(status.String());
	if (fPassword->Text()[0] == '\0')
		fPassword->MakeFocus(true);
}


// Saves the form as a favorite; an existing favorite with the same name is
// updated.
void
MounterWindow::_AddFavorite(const char* name)
{
	Favorite favorite;
	_CurrentFavorite(favorite);
	favorite.name = name;

	int32 index = _FindFavorite(name);
	bool existed = index >= 0;
	if (existed) {
		FavoriteItem* item = dynamic_cast<FavoriteItem*>(
			fFavoritesList->ItemAt(index));
		if (item != NULL) {
			item->Data() = favorite;
			fFavoritesList->InvalidateItem(index);
		}
	} else {
		fFavoritesList->AddItem(new FavoriteItem(favorite));
		index = fFavoritesList->CountItems() - 1;
	}
	fFavoritesList->Select(index);
	fFavoritesList->ScrollToSelection();

	// Store the password now if asked to, so that the favorite is complete
	// before the first mount.
	if (favorite.remember && fPassword->Text()[0] != '\0')
		_StorePassword();
	_SaveSettings();

	BString status(existed ? "Updated favorite \"" : "Added favorite \"");
	status << name << "\"";
	fStatus->SetText(status.String());
}


void
MounterWindow::_PromptForName(const char* title, const char* initialName,
	const BMessage& result)
{
	NamePromptWindow* window = new NamePromptWindow(this, title, initialName,
		result);
	window->Show();
}


// #pragma mark - settings


static status_t
settings_path(BPath& path)
{
	status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	if (status != B_OK)
		return status;
	return path.Append(kSettingsFileName);
}


void
MounterWindow::_LoadSettings()
{
	BPath path;
	if (settings_path(path) != B_OK)
		return;
	BFile file(path.Path(), B_READ_ONLY);
	BMessage settings;
	if (file.InitCheck() != B_OK || settings.Unflatten(&file) != B_OK)
		return;

	const char* value;
	if (settings.FindString("server", &value) == B_OK)
		fServer->SetText(value);
	if (settings.FindString("share", &value) == B_OK)
		fShare->SetText(value);
	if (settings.FindString("user", &value) == B_OK)
		fUser->SetText(value);
	if (settings.FindString("domain", &value) == B_OK)
		fDomain->SetText(value);
	if (settings.FindString("mountpoint", &value) == B_OK
		&& value[0] != '\0') {
		fMountPoint->SetText(value);
		fMountPointEdited = true;
	}
	bool flag;
	if (settings.FindBool("sign", &flag) == B_OK)
		fSign->SetValue(flag ? B_CONTROL_ON : B_CONTROL_OFF);
	if (settings.FindBool("seal", &flag) == B_OK)
		fSeal->SetValue(flag ? B_CONTROL_ON : B_CONTROL_OFF);
	if (settings.FindBool("readonly", &flag) == B_OK)
		fReadOnly->SetValue(flag ? B_CONTROL_ON : B_CONTROL_OFF);
	if (settings.FindBool("remember", &flag) == B_OK)
		fRemember->SetValue(flag ? B_CONTROL_ON : B_CONTROL_OFF);
	BRect frame;
	if (settings.FindRect("frame", &frame) == B_OK) {
		MoveTo(frame.LeftTop());
		ResizeTo(frame.Width(), frame.Height());
	}
	_LoadFavorites(settings);
	_LoadPassword();
}


void
MounterWindow::_SaveSettings()
{
	BPath path;
	if (settings_path(path) != B_OK)
		return;
	BMessage settings;
	settings.AddString("server", fServer->Text());
	settings.AddString("share", fShare->Text());
	settings.AddString("user", fUser->Text());
	settings.AddString("domain", fDomain->Text());
	BString defaultMountPoint("/");
	defaultMountPoint << fShare->Text();
	settings.AddString("mountpoint",
		defaultMountPoint == fMountPoint->Text() ? "" : fMountPoint->Text());
	settings.AddBool("sign", fSign->Value() == B_CONTROL_ON);
	settings.AddBool("seal", fSeal->Value() == B_CONTROL_ON);
	settings.AddBool("readonly", fReadOnly->Value() == B_CONTROL_ON);
	settings.AddBool("remember", fRemember->Value() == B_CONTROL_ON);
	settings.AddRect("frame", Frame());
	_SaveFavorites(settings);

	BFile file(path.Path(), B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
	if (file.InitCheck() == B_OK)
		settings.Flatten(&file);
}


// #pragma mark - MounterApplication


class MounterApplication : public BApplication {
public:
								MounterApplication();

	virtual	void				ReadyToRun();
	virtual	void				ArgvReceived(int32 argc, char** argv);
	virtual	void				RefsReceived(BMessage* message);
	virtual	void				MessageReceived(BMessage* message);

private:
			MounterWindow*		fWindow;
			BString				fServer;
			BString				fShare;
			BMessage			fFields;
};


MounterApplication::MounterApplication()
	:
	BApplication(kApplicationSignature),
	fWindow(NULL)
{
}


void
MounterApplication::ReadyToRun()
{
	fWindow = new MounterWindow();
	if (fServer.Length() > 0)
		fWindow->SetShare(fServer.String(), fShare.String());
	char* name;
	type_code type;
	for (int32 i = 0; fFields.GetInfo(B_STRING_TYPE, i, &name, &type) == B_OK;
			i++) {
		const char* value;
		if (fFields.FindString(name, &value) == B_OK)
			fWindow->SetField(name, value);
	}
	fWindow->Show();
}


void
MounterApplication::ArgvReceived(int32 argc, char** argv)
{
	// Accept an //server/share argument, plus key=value arguments for the
	// other fields (user, password, domain, mountpoint) and the flags
	// sign, seal and ro.
	for (int32 i = 1; i < argc; i++) {
		BString unc(argv[i]);
		unc.ReplaceAll('\\', '/');
		if (!unc.StartsWith("//")) {
			BString argument(argv[i]);
			int32 equals = argument.FindFirst('=');
			BString key(argument);
			BString value;
			if (equals >= 0) {
				key.Truncate(equals);
				value = argument.String() + equals + 1;
			}
			fFields.RemoveName(key.String());
			fFields.AddString(key.String(), value.String());
			if (fWindow != NULL && fWindow->Lock()) {
				fWindow->SetField(key.String(), value.String());
				fWindow->Unlock();
			}
			continue;
		}
		unc.RemoveFirst("//");
		int32 slash = unc.FindFirst('/');
		if (slash <= 0)
			continue;
		fServer = unc;
		fServer.Truncate(slash);
		fShare = unc.String() + slash + 1;
		if (fWindow != NULL && fWindow->Lock()) {
			fWindow->SetShare(fServer.String(), fShare.String());
			fWindow->Unlock();
		}
	}
}


void
MounterApplication::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgMount:
		case kMsgUnmount:
		case kMsgRefresh:
		{
			// Allow scripting, e.g. "hey SMBMounter 'mnt '".
			if (fWindow != NULL)
				fWindow->PostMessage(message);
			BMessage reply(B_REPLY);
			message->SendReply(&reply);
			break;
		}
		default:
			BApplication::MessageReceived(message);
	}
}


void
MounterApplication::RefsReceived(BMessage* message)
{
	// Launched as a Tracker add-on: nothing to do with the selected entries,
	// just show the window (which already happens in ReadyToRun()).
	if (fWindow != NULL && fWindow->Lock()) {
		fWindow->Activate();
		fWindow->Unlock();
	}
}


int
main()
{
	MounterApplication app;
	app.Run();
	return 0;
}
