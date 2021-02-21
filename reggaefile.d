import reggae;
mixin build!(dubConfigurationTarget!(Configuration("standalone"),
                                     CompilerFlags("-w -g -debug")));
