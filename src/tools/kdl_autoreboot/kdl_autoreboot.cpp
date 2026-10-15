/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * kdl_autoreboot - a kernel debugger add-on for unattended test machines.
 * When the kernel enters the kernel debugger (panic), it types "bt" and
 * then "reboot" at the KDL prompt, so that the machine reboots on its own
 * and the panic message plus stack trace end up in /var/log/previous_syslog.
 *
 * Install to /boot/home/config/non-packaged/add-ons/kernel/debugger/ and
 * reboot. Remove the file to get interactive KDL back.
 */


#include <debug.h>
#include <KernelExport.h>
#include <module.h>


static const char kCommands[] = "bt\nreboot\n";
static int sPosition = -1;


static void
enter_debugger(void)
{
	sPosition = 0;
}


static void
exit_debugger(void)
{
	sPosition = -1;
}


static int
debugger_getchar(void)
{
	if (sPosition < 0 || kCommands[sPosition] == '\0')
		return -1;
	return (unsigned char)kCommands[sPosition++];
}


static status_t
std_ops(int32 op, ...)
{
	switch (op) {
		case B_MODULE_INIT:
			dprintf("kdl_autoreboot: active, the machine will reboot after a "
				"kernel panic\n");
			return B_OK;
		case B_MODULE_UNINIT:
			return B_OK;
	}
	return B_BAD_VALUE;
}


static debugger_module_info sModuleInfo = {
	{
		"debugger/kdl_autoreboot/v1",
		0,
		&std_ops
	},
	&enter_debugger,
	&exit_debugger,
	NULL,	// debugger_puts
	&debugger_getchar,
	NULL	// emergency_key_pressed
};


module_info* modules[] = {
	(module_info*)&sModuleInfo,
	NULL
};
