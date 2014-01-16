use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'CSP',
    'VERSION_FROM' => 'CSP.pm', # finds $VERSION
    'EXE_FILES' => ['csp'],
    'PREREQ_PM' => { 'Date::Calc' => 0 , 'Term::Prompt' => 0.10, 'IPC::Run' => 0 }
);
