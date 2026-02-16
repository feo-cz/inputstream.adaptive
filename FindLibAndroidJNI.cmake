# - Find LibAndroidJNI
# Once done this will define
#
#   LIBANDROIDJNI_FOUND        - True if LibAndroidJNI found.
#   LIBANDROIDJNI_INCLUDE_DIRS - where to find androidjni
#

find_path(LIBANDROIDJNI_INCLUDE_DIRS include/androidjni)
find_library(LIBANDROIDJNI_LIBRARIES androidjni)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibAndroidJNI REQUIRED_VARS LIBANDROIDJNI_INCLUDE_DIRS LIBANDROIDJNI_LIBRARIES)

mark_as_advanced(LIBANDROIDJNI_INCLUDE_DIRS LIBANDROIDJNI_LIBRARIES)
