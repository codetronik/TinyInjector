LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := injector
LOCAL_SRC_FILES := main.cpp injector.cpp ptrace.cpp utils.cpp
LOCAL_LDFLAGS += -pie

include $(BUILD_EXECUTABLE)
