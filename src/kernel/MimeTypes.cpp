/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */


#include "MimeTypes.h"

#include <string.h>


struct mime_entry {
	const char*	extension;
	const char*	type;
};

static const mime_entry kMimeTypes[] = {
	// text and source
	{"txt", "text/plain"}, {"text", "text/plain"}, {"log", "text/plain"},
	{"md", "text/x-markdown"}, {"markdown", "text/x-markdown"},
	{"html", "text/html"}, {"htm", "text/html"}, {"xhtml", "text/html"},
	{"css", "text/css"}, {"xml", "text/xml"}, {"csv", "text/csv"},
	{"json", "application/json"}, {"yaml", "text/x-yaml"},
	{"yml", "text/x-yaml"}, {"ini", "text/plain"}, {"cfg", "text/plain"},
	{"conf", "text/plain"}, {"rtf", "text/rtf"}, {"tex", "text/x-tex"},
	{"c", "text/x-source-code"}, {"cc", "text/x-source-code"},
	{"cpp", "text/x-source-code"}, {"cxx", "text/x-source-code"},
	{"h", "text/x-source-code"}, {"hpp", "text/x-source-code"},
	{"hh", "text/x-source-code"}, {"m", "text/x-source-code"},
	{"mm", "text/x-source-code"}, {"java", "text/x-source-code"},
	{"py", "text/x-source-code"}, {"rb", "text/x-source-code"},
	{"pl", "text/x-source-code"}, {"php", "text/x-source-code"},
	{"js", "text/x-source-code"}, {"ts", "text/x-source-code"},
	{"go", "text/x-source-code"}, {"rs", "text/x-source-code"},
	{"lua", "text/x-source-code"}, {"sh", "text/x-source-code"},
	{"bash", "text/x-source-code"}, {"asm", "text/x-source-code"},
	{"s", "text/x-source-code"}, {"pas", "text/x-source-code"},
	{"rdef", "text/x-vnd.Be.ResourceDef"}, {"jam", "text/x-jamfile"},
	{"makefile", "text/x-makefile"}, {"mk", "text/x-makefile"},
	{"diff", "text/x-patch"}, {"patch", "text/x-patch"},
	{"sql", "text/x-sql"}, {"vcf", "text/x-vcard"}, {"ics", "text/calendar"},
	{"nfo", "text/plain"}, {"srt", "text/plain"}, {"sub", "text/plain"},

	// images
	{"png", "image/png"}, {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"},
	{"jpe", "image/jpeg"}, {"gif", "image/gif"}, {"bmp", "image/x-bmp"},
	{"tif", "image/tiff"}, {"tiff", "image/tiff"}, {"ico", "image/x-icon"},
	{"svg", "image/svg+xml"}, {"webp", "image/webp"}, {"tga", "image/x-tga"},
	{"pcx", "image/x-pcx"}, {"ppm", "image/x-portable-pixmap"},
	{"pgm", "image/x-portable-graymap"}, {"pbm", "image/x-portable-bitmap"},
	{"pnm", "image/x-portable-anymap"}, {"psd", "image/x-photoshop"},
	{"xcf", "image/x-xcf"}, {"heic", "image/heic"}, {"heif", "image/heif"},
	{"avif", "image/avif"}, {"jp2", "image/jp2"}, {"exr", "image/x-exr"},
	{"hdr", "image/vnd.radiance"}, {"dds", "image/x-dds"},
	{"raw", "image/x-raw"}, {"cr2", "image/x-canon-cr2"},
	{"nef", "image/x-nikon-nef"}, {"dng", "image/x-adobe-dng"},

	// audio
	{"mp3", "audio/mpeg"}, {"mp2", "audio/mpeg"}, {"mpga", "audio/mpeg"},
	{"ogg", "audio/ogg"}, {"oga", "audio/ogg"}, {"opus", "audio/ogg"},
	{"flac", "audio/x-flac"}, {"wav", "audio/x-wav"}, {"aif", "audio/x-aiff"},
	{"aiff", "audio/x-aiff"}, {"aifc", "audio/x-aiff"}, {"m4a", "audio/mp4"},
	{"aac", "audio/aac"}, {"wma", "audio/x-ms-wma"}, {"mid", "audio/midi"},
	{"midi", "audio/midi"}, {"ape", "audio/x-ape"}, {"mka", "audio/x-matroska"},
	{"mod", "audio/x-mod"}, {"xm", "audio/x-xm"}, {"it", "audio/x-it"},
	{"s3m", "audio/x-s3m"}, {"au", "audio/basic"}, {"snd", "audio/basic"},
	{"ac3", "audio/ac3"}, {"dts", "audio/vnd.dts"}, {"wv", "audio/x-wavpack"},
	{"m3u", "audio/x-mpegurl"}, {"pls", "audio/x-scpls"},

	// video
	{"mp4", "video/mp4"}, {"m4v", "video/mp4"}, {"mkv", "video/x-matroska"},
	{"webm", "video/webm"}, {"avi", "video/x-msvideo"}, {"mov", "video/quicktime"},
	{"qt", "video/quicktime"}, {"mpg", "video/mpeg"}, {"mpeg", "video/mpeg"},
	{"mpe", "video/mpeg"}, {"m2v", "video/mpeg"}, {"ts", "video/mp2t"},
	{"m2ts", "video/mp2t"}, {"mts", "video/mp2t"}, {"vob", "video/mpeg"},
	{"wmv", "video/x-ms-wmv"}, {"asf", "video/x-ms-asf"}, {"flv", "video/x-flv"},
	{"f4v", "video/mp4"}, {"3gp", "video/3gpp"}, {"3g2", "video/3gpp2"},
	{"ogv", "video/ogg"}, {"ogm", "video/ogg"}, {"divx", "video/x-msvideo"},
	{"rm", "application/vnd.rn-realmedia"}, {"rmvb", "application/vnd.rn-realmedia"},
	{"dv", "video/dv"}, {"y4m", "video/x-yuv4mpeg"},

	// archives and packages
	{"zip", "application/zip"}, {"gz", "application/x-gzip"},
	{"tgz", "application/x-gzip"}, {"bz2", "application/x-bzip2"},
	{"tbz", "application/x-bzip2"}, {"xz", "application/x-xz"},
	{"txz", "application/x-xz"}, {"zst", "application/zstd"},
	{"lz", "application/x-lzip"}, {"lzma", "application/x-lzma"},
	{"tar", "application/x-tar"}, {"7z", "application/x-7z-compressed"},
	{"rar", "application/x-rar-compressed"}, {"cab", "application/vnd.ms-cab-compressed"},
	{"deb", "application/x-debian-package"}, {"rpm", "application/x-rpm"},
	{"hpkg", "application/x-vnd.haiku-package"},
	{"hpkr", "application/x-vnd.haiku-package-repository"},
	{"iso", "application/x-cd-image"}, {"img", "application/x-cd-image"},
	{"dmg", "application/x-apple-diskimage"}, {"jar", "application/x-java-archive"},
	{"apk", "application/vnd.android.package-archive"},
	{"msi", "application/x-msi"}, {"exe", "application/x-msdownload"},
	{"dll", "application/x-msdownload"},

	// documents
	{"pdf", "application/pdf"}, {"ps", "application/postscript"},
	{"eps", "application/postscript"}, {"epub", "application/epub+zip"},
	{"mobi", "application/x-mobipocket-ebook"}, {"djvu", "image/vnd.djvu"},
	{"doc", "application/msword"},
	{"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	{"xls", "application/vnd.ms-excel"},
	{"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	{"ppt", "application/vnd.ms-powerpoint"},
	{"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
	{"odt", "application/vnd.oasis.opendocument.text"},
	{"ods", "application/vnd.oasis.opendocument.spreadsheet"},
	{"odp", "application/vnd.oasis.opendocument.presentation"},
	{"odg", "application/vnd.oasis.opendocument.graphics"},
	{"abw", "application/x-abiword"}, {"chm", "application/vnd.ms-htmlhelp"},

	// fonts and misc
	{"ttf", "application/x-truetype-font"}, {"otf", "application/x-font-otf"},
	{"woff", "application/font-woff"}, {"woff2", "font/woff2"},
	{"swf", "application/x-shockwave-flash"}, {"torrent", "application/x-bittorrent"},
	{"bin", "application/octet-stream"}, {"dat", "application/octet-stream"},
	{"sqlite", "application/x-sqlite3"}, {"db", "application/x-sqlite3"},
	{"vcard", "text/x-vcard"}, {"kml", "application/vnd.google-earth.kml+xml"},
	{"gpx", "application/gpx+xml"}, {"stl", "model/stl"}, {"obj", "model/obj"},
	{"blend", "application/x-blender"},
	{NULL, NULL}
};


static int
compare_case_insensitive(const char* a, const char* b)
{
	while (*a != '\0' && *b != '\0') {
		char ca = *a, cb = *b;
		if (ca >= 'A' && ca <= 'Z')
			ca = (char)(ca - 'A' + 'a');
		if (cb >= 'A' && cb <= 'Z')
			cb = (char)(cb - 'A' + 'a');
		if (ca != cb)
			return ca - cb;
		a++;
		b++;
	}
	return *a - *b;
}


const char*
mime_type_for_file_name(const char* name)
{
	if (name == NULL)
		return NULL;
	const char* dot = strrchr(name, '.');
	if (dot == NULL || dot == name || dot[1] == '\0')
		return NULL;
	const char* extension = dot + 1;
	// extremely long "extensions" are not extensions
	if (strlen(extension) > 12)
		return NULL;
	for (int i = 0; kMimeTypes[i].extension != NULL; i++) {
		if (compare_case_insensitive(kMimeTypes[i].extension, extension) == 0)
			return kMimeTypes[i].type;
	}
	return NULL;
}
