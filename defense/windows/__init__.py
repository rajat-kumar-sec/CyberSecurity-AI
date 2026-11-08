"""Windows integration for the defensive-actions subsystem.

Everything Windows-specific lives here: fixed-argv inspection, the firewall
command builder and the one-shot UAC helper. The rest of the package imports
this module lazily, so the application still starts on other platforms.
"""
