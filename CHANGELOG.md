# tiffy Changelog

### 1.0.4
    #### Changes
    - added support for TIE data types
    - added support to create txt files
    - added gitignore entry to ignore existing feed files

### 1.0.2
   #### Changes
   - added threshold setting for IDS flag in config
   - tagging for attributes derived from TIE observations added
   - removed unused config values base_severity and base_confidence
   
   #### Bugfixes
   - Fixed Bug with logging when no log_path was provided

### 1.0.1
   #### Changes
   - simplified Config File format, added possibility to use environment variables for configuration (see readme)
   - added parameter to change log saving location
   - loglvl now takes string values, e.g. DEBUG or INFO
   - removed unused config values and parameters (e.g. Attributes_Tagging)
   - added flag to diasble certificate validation (needed in some proxy setups)
   
   #### Bugfixes
   - Fixed Attributes to_ids config value not being used / not working
   - Fixed Event Published config value not being used / not working
   - Fixed http proxy not being used as https proxy if no specific https proxy was given
   - Fixed https proxy parameter unnecessarily enforcing https scheme
   
   