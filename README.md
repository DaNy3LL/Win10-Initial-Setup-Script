## Description

This is a PowerShell script for automation of routine tasks done after fresh installations of Windows 10 and Windows Server 2016. This is by no means any complete set of all existing Windows tweaks and neither is it another "antispying" type of script. It's simply a setting which I like to use and which in my opinion make the system less obtrusive.

## Usage
If you just want to run the script with default preset, simply double click on *ExecuteScript.bat* and then you will be asked if you want to run the script as an Administrator.

### Advanced usage
The script consists of separate functions, each of which contains one tweak. The functions can be grouped to *presets*. Preset is simply a list of function names which should be called. If you don't supply any specific preset, the default preset defined by `$tweaks` array in the beginning of the script will be applied. Any function which is not present or is commented in a preset will not be called, thus the corresponding tweak will not be applied. If you choose to fork the script and adjust the defaults instead of creating a customized preset file, then all you have to modify is the `$tweaks` array.

To supply a customized preset, you can either pass the function names directly as parameters.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tweaks.ps1 EnableFirewall EnableDefender

Or you can create a file where you write the function names (one function name per line, no commas, whitespaces allowed, comments on separate lines starting with `#`) and then pass the filename using *-preset* parameter.
Example of a preset file `mypreset.txt`:

    # Security tweaks
    EnableFirewall
    EnableDefender

    # UI tweaks
    ShowKnownExtensions
    ShowHiddenFiles

Command using the preset file above:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tweaks.ps1 -preset mypreset.txt

## FAQ

**Q:** Can I run the script safely?  
**A:** Definitely not. You have to understand what the functions do and what will be the implications for you if you run them. Some functions lower security, hide controls or uninstall applications. **If you're not sure what the script does, do not attempt to run it!**

**Q:** Can I run the script repeatedly?  
**A:** Yes! In fact the script has been written to support exactly this as it's not uncommon that big Windows Updates reset some of the settings.

**Q:** Can I run the script in multi-user environment?  
**A:** Yes, to certain extent. Some tweaks (most notably UI tweaks) are set only for the user currently executing the script. As stated above, the script can be run repeatedly; therefore it's possible to run it multiple times, each time as different user. Due to the nature of authentication and privilege escalation mechanisms in Windows, the script can be successfully applied only for users belonging to *Administrators* group. Standard users will get an UAC prompt asking for admin credentials which then causes the tweaks to be applied to the given admin account instead of the original non-privileged one. To circumvent this, add the standard user to the *Administrators* group, run the script, and then remove the user from *Administrators* group again. There are a few ways how the same functionality can be achieved programmatically, but I'm not planning to include any of them as it would negatively impact code complexity and readability.

**Q:** Can I run the script on Windows Server 2016?  
**A:** Yes. Starting from version 2.5, Windows Server 2016 is supported. There are even few tweaks specific to Server environment. Keep in mind though, that the script is still primarily designed for Windows 10, so you have to create your own preset for Windows Server 2016.

**Q:** Can I run the script on Windows 7, 8, 8.1 or other versions of Windows?  
**A:** No. Although some tweaks may work also on older versions of Windows, the script is developed only for Windows 10 and Windows Server 2016. There are no plans to add support for older versions.

**Q:** Did you test the script?  
**A:** Yes. I'm testing new additions on up-to-date Home and Enterprise editions in VMs. I'm also regularly using it for all my home installations after all bigger updates.

**Q**: I've run the script and it did xxx, how can I undo it?  
**A:** For every tweak, there is also a corresponding function which restores the default settings. The default is considered freshly installed Windows 10 or Windows Server 2016 with no adjustments made during or after the installation. Use the tweaks to create and run new preset. Alternatively, since most functions are just automation for actions which can be done using GUI, find appropriate control and modify it manually.

**Q:** I've run the script and it broke my computer / killed neighbor's dog / caused world war 3.  
**A:** I don't care. Also, that's not a question.

**Q:** I'm using a tweak for xxx on my installation, can you add it?  
**A:** Submit a PR or drop me a message. If I find the functionality simple, useful and not dependent on any 3rd party modules or executables, I might add it.

**Q:** Can I use the script or modify it for my / my company's needs?  
**A:** Sure, knock yourself out. Just don't forget to include copyright notice as per MIT license requirements. I'd also suggest including a link to this GitHub repo as it's very likely that something will be changed, added or improved to keep track with future versions of Windows 10.

**Q:** Why are there repeated pieces of code throughout some functions?  
**A:** So you can directly take the function block and use it elsewhere, without elaborating on any dependencies.

**Q:** For how long are you going to maintain the script?  
**A:** As long as I use Windows 10.
