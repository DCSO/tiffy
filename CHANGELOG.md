# tiffy Changelog

### 1.0.1
   #### Changes
   - simplified Config File format, added possibility to use environment variables for configuration (see readme)
   - added parameter to change log saving location
   - loglvl now takes string values, e.g. DEBUG or INFO
   - removed unused config values and parameters (e.g. Attributes_Tagging)
   - added flag to diasble certificate validation (needed in some proxy setups)
   
   #### Bugfixes
   - Fixed Attributes to_ids config value not beeing used / not working
   - Fixed http proxy not being used as https proxy if no specific https proxy was given
   - fixed https proxy parameter unnecessarily enforcing https scheme
   
   