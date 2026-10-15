// Probe: performs the calls Tracker makes when a document is double-clicked
// (type lookup, FindApp, forced MIME update) and reports what happens.
#include <stdio.h>
#include <string.h>
#include <Application.h>
#include <Entry.h>
#include <Mime.h>
#include <Node.h>
#include <NodeInfo.h>
#include <Path.h>
#include <Roster.h>
#include <fs_attr.h>

int
main(int argc, char** argv)
{
	if (argc < 2) { fprintf(stderr, "usage: launchcheck <file>\n"); return 1; }
	BApplication app("application/x-vnd.HaikuSMB-launchcheck");
	entry_ref ref;
	get_ref_for_path(argv[1], &ref);
	BNode node(&ref);
	BNodeInfo info(&node);
	char type[B_MIME_TYPE_LENGTH] = "";
	status_t status = info.GetType(type);
	printf("GetType: %s (%s)\n", strerror(status), type);
	entry_ref appRef;
	status = be_roster->FindApp(&ref, &appRef);
	printf("FindApp: %s (%s)\n", strerror(status), status == B_OK ? appRef.name : "-");
	status = node.RemoveAttr("BEOS:TYPE");
	printf("RemoveAttr BEOS:TYPE: %s\n", strerror(status));
	BPath path(&ref);
	status = update_mime_info(path.Path(), 0, 1, 1);
	printf("update_mime_info: %s\n", strerror(status));
	status = info.GetType(type);
	printf("GetType after update: %s (%s)\n", strerror(status), type);
	status = be_roster->FindApp(&ref, &appRef);
	printf("FindApp after update: %s (%s)\n", strerror(status), status == B_OK ? appRef.name : "-");
	BMimeType guessed;
	status = BMimeType::GuessMimeType(&ref, &guessed);
	printf("GuessMimeType: %s (%s)\n", strerror(status), guessed.Type());
	return 0;
}
