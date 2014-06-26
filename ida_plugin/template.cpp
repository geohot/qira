#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

int IDAP_init(void)
{
	// Do checks here to ensure your plug-in is being used within
	// an environment it was written for. Return PLUGIN_SKIP if the 	
	// checks fail, otherwise return PLUGIN_KEEP.
	
	return PLUGIN_KEEP;
}

void IDAP_term(void)
{
	// Stuff to do when exiting, generally you'd put any sort
	// of clean-up jobs here.
	return;
}

// The plugin can be passed an integer argument from the plugins.cfg
// file. This can be useful when you want the one plug-in to do
// something different depending on the hot-key pressed or menu
// item selected.
void IDAP_run(int arg)
{
	// The "meat" of your plug-in
	msg("Hello world!");
	return;
}

// There isn't much use for these yet, but I set them anyway.
char IDAP_comment[] 	= "This is my test plug-in";
char IDAP_help[] 		= "My plugin";

// The name of the plug-in displayed in the Edit->Plugins menu. It can 
// be overridden in the user's plugins.cfg file.
char IDAP_name[] 		= "My plugin";

// The hot-key the user can use to run your plug-in.
char IDAP_hotkey[] 	= "Alt-X";

// The all-important exported PLUGIN object
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
  0,					// Flags (see below)
  IDAP_init,			// Initialisation function
  IDAP_term,			// Clean-up function
  IDAP_run,				// Main plug-in body
  IDAP_comment,			// Comment – unused
  IDAP_help,			// As above – unused
  IDAP_name,			// Plug-in name shown in 
						// Edit->Plugins menu
  IDAP_hotkey			// Hot key to run the plug-in
};
