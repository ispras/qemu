include ../config-host.mak
include config-target.mak
include $(SRC_PATH)/rules.mak

PLUGIN_PREFIX := plugin-
export PLUGIN_PREFIX

PLUGINS :=
PLUGINS += contexts
PLUGINS += example1 example2
PLUGINS += mem_log
ifeq ($(TARGET_NAME), $(filter $(TARGET_NAME), i386 x86_64))
PLUGINS += syscalls_windows_xp syscalls_windows_7
PLUGINS += syscalls_linux
ifeq ($(TARGET_NAME), $(filter $(TARGET_NAME), i386))
PLUGINS += syscalls_windows_8 syscalls_windows_8.1
endif
PLUGINS += file_monitor
#PLUGINS += syscalls_linux
endif
ifeq ($(TARGET_NAME), $(filter $(TARGET_NAME), i386))
PLUGINS += api_monitor_windows
PLUGINS += api_monitor_linux
endif

PLUGINS := $(addsuffix .plugin,$(PLUGINS))

.PHONY: all clean install install-libexec

%.plugin:
	@$(MAKE) -C . -f $(SRC_PATH)/plugins/plugins_src/Makefile.plugins V="$(V)" PLUGIN="$*" $(MAKECMDGOALS)

all: $(PLUGINS)
	@true

clean: $(PLUGINS)
	@true

install: install-libexec $(PLUGINS)
	@true

install-libexec:
	$(INSTALL_DIR) "$(DESTDIR)$(libexecdir)"
