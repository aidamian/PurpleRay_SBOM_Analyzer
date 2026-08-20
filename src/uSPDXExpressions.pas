(**
  PurpleRay SBOM Analyzer SPDX-expression validation unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Validates bounded SPDX license expressions without network access or runtime
  dependencies, using a registry pinned to the CycloneDX 1.6 schema bundle.

  Citation request
  ----------------
  Please retain this notice and cite the project as follows:

  @misc{damian2026purpleraysbomanalyzer,
    author = {Andrei Ionut Damian},
    title  = {{PurpleRay SBOM Analyzer}},
    year   = {2026},
    url    = {https://github.com/aidamian/PurpleRay_SBOM_Analyzer}
  }
*)
unit uSPDXExpressions;

{$mode objfpc}{$H+}

interface

{**
  Determines whether text is one bounded, registry-backed SPDX expression.

  Parameters
  ----------
  AValue
    Single-line candidate using case-sensitive SPDX identifiers, space-delimited
    uppercase ``AND``, ``OR``, and ``WITH`` operators, and an adjacent optional
    ``+`` suffix.

  Returns
  -------
  Boolean
    True only when the complete input follows the supported SPDX grammar.

  Raises
  ------
  None
}
function IsValidSPDXExpression(const AValue: string): Boolean;

implementation

uses
  SysUtils;

const
  SPDXRegistryRevision =
    'CycloneDX specification commit 8a27bfd1be5be0dcb2c208a34d2f4fa0b6d75bd7; ' +
    'spdx.schema.json SHA-256 c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6';
  SPDXLicenseIdentifiers: array[0..658] of string = (
    '0BSD',
    '3D-Slicer-1.0',
    'AAL',
    'Abstyles',
    'AdaCore-doc',
    'Adobe-2006',
    'Adobe-Display-PostScript',
    'Adobe-Glyph',
    'Adobe-Utopia',
    'ADSL',
    'AFL-1.1',
    'AFL-1.2',
    'AFL-2.0',
    'AFL-2.1',
    'AFL-3.0',
    'Afmparse',
    'AGPL-1.0',
    'AGPL-1.0-only',
    'AGPL-1.0-or-later',
    'AGPL-3.0',
    'AGPL-3.0-only',
    'AGPL-3.0-or-later',
    'Aladdin',
    'AMD-newlib',
    'AMDPLPA',
    'AML',
    'AML-glslang',
    'AMPAS',
    'ANTLR-PD',
    'ANTLR-PD-fallback',
    'any-OSI',
    'Apache-1.0',
    'Apache-1.1',
    'Apache-2.0',
    'APAFML',
    'APL-1.0',
    'App-s2p',
    'APSL-1.0',
    'APSL-1.1',
    'APSL-1.2',
    'APSL-2.0',
    'Arphic-1999',
    'Artistic-1.0',
    'Artistic-1.0-cl8',
    'Artistic-1.0-Perl',
    'Artistic-2.0',
    'ASWF-Digital-Assets-1.0',
    'ASWF-Digital-Assets-1.1',
    'Baekmuk',
    'Bahyph',
    'Barr',
    'bcrypt-Solar-Designer',
    'Beerware',
    'Bitstream-Charter',
    'Bitstream-Vera',
    'BitTorrent-1.0',
    'BitTorrent-1.1',
    'blessing',
    'BlueOak-1.0.0',
    'Boehm-GC',
    'Borceux',
    'Brian-Gladman-2-Clause',
    'Brian-Gladman-3-Clause',
    'BSD-1-Clause',
    'BSD-2-Clause',
    'BSD-2-Clause-Darwin',
    'BSD-2-Clause-first-lines',
    'BSD-2-Clause-FreeBSD',
    'BSD-2-Clause-NetBSD',
    'BSD-2-Clause-Patent',
    'BSD-2-Clause-Views',
    'BSD-3-Clause',
    'BSD-3-Clause-acpica',
    'BSD-3-Clause-Attribution',
    'BSD-3-Clause-Clear',
    'BSD-3-Clause-flex',
    'BSD-3-Clause-HP',
    'BSD-3-Clause-LBNL',
    'BSD-3-Clause-Modification',
    'BSD-3-Clause-No-Military-License',
    'BSD-3-Clause-No-Nuclear-License',
    'BSD-3-Clause-No-Nuclear-License-2014',
    'BSD-3-Clause-No-Nuclear-Warranty',
    'BSD-3-Clause-Open-MPI',
    'BSD-3-Clause-Sun',
    'BSD-4-Clause',
    'BSD-4-Clause-Shortened',
    'BSD-4-Clause-UC',
    'BSD-4.3RENO',
    'BSD-4.3TAHOE',
    'BSD-Advertising-Acknowledgement',
    'BSD-Attribution-HPND-disclaimer',
    'BSD-Inferno-Nettverk',
    'BSD-Protection',
    'BSD-Source-beginning-file',
    'BSD-Source-Code',
    'BSD-Systemics',
    'BSD-Systemics-W3Works',
    'BSL-1.0',
    'BUSL-1.1',
    'bzip2-1.0.5',
    'bzip2-1.0.6',
    'C-UDA-1.0',
    'CAL-1.0',
    'CAL-1.0-Combined-Work-Exception',
    'Caldera',
    'Caldera-no-preamble',
    'Catharon',
    'CATOSL-1.1',
    'CC-BY-1.0',
    'CC-BY-2.0',
    'CC-BY-2.5',
    'CC-BY-2.5-AU',
    'CC-BY-3.0',
    'CC-BY-3.0-AT',
    'CC-BY-3.0-AU',
    'CC-BY-3.0-DE',
    'CC-BY-3.0-IGO',
    'CC-BY-3.0-NL',
    'CC-BY-3.0-US',
    'CC-BY-4.0',
    'CC-BY-NC-1.0',
    'CC-BY-NC-2.0',
    'CC-BY-NC-2.5',
    'CC-BY-NC-3.0',
    'CC-BY-NC-3.0-DE',
    'CC-BY-NC-4.0',
    'CC-BY-NC-ND-1.0',
    'CC-BY-NC-ND-2.0',
    'CC-BY-NC-ND-2.5',
    'CC-BY-NC-ND-3.0',
    'CC-BY-NC-ND-3.0-DE',
    'CC-BY-NC-ND-3.0-IGO',
    'CC-BY-NC-ND-4.0',
    'CC-BY-NC-SA-1.0',
    'CC-BY-NC-SA-2.0',
    'CC-BY-NC-SA-2.0-DE',
    'CC-BY-NC-SA-2.0-FR',
    'CC-BY-NC-SA-2.0-UK',
    'CC-BY-NC-SA-2.5',
    'CC-BY-NC-SA-3.0',
    'CC-BY-NC-SA-3.0-DE',
    'CC-BY-NC-SA-3.0-IGO',
    'CC-BY-NC-SA-4.0',
    'CC-BY-ND-1.0',
    'CC-BY-ND-2.0',
    'CC-BY-ND-2.5',
    'CC-BY-ND-3.0',
    'CC-BY-ND-3.0-DE',
    'CC-BY-ND-4.0',
    'CC-BY-SA-1.0',
    'CC-BY-SA-2.0',
    'CC-BY-SA-2.0-UK',
    'CC-BY-SA-2.1-JP',
    'CC-BY-SA-2.5',
    'CC-BY-SA-3.0',
    'CC-BY-SA-3.0-AT',
    'CC-BY-SA-3.0-DE',
    'CC-BY-SA-3.0-IGO',
    'CC-BY-SA-4.0',
    'CC-PDDC',
    'CC0-1.0',
    'CDDL-1.0',
    'CDDL-1.1',
    'CDL-1.0',
    'CDLA-Permissive-1.0',
    'CDLA-Permissive-2.0',
    'CDLA-Sharing-1.0',
    'CECILL-1.0',
    'CECILL-1.1',
    'CECILL-2.0',
    'CECILL-2.1',
    'CECILL-B',
    'CECILL-C',
    'CERN-OHL-1.1',
    'CERN-OHL-1.2',
    'CERN-OHL-P-2.0',
    'CERN-OHL-S-2.0',
    'CERN-OHL-W-2.0',
    'CFITSIO',
    'check-cvs',
    'checkmk',
    'ClArtistic',
    'Clips',
    'CMU-Mach',
    'CMU-Mach-nodoc',
    'CNRI-Jython',
    'CNRI-Python',
    'CNRI-Python-GPL-Compatible',
    'COIL-1.0',
    'Community-Spec-1.0',
    'Condor-1.1',
    'copyleft-next-0.3.0',
    'copyleft-next-0.3.1',
    'Cornell-Lossless-JPEG',
    'CPAL-1.0',
    'CPL-1.0',
    'CPOL-1.02',
    'Cronyx',
    'Crossword',
    'CrystalStacker',
    'CUA-OPL-1.0',
    'Cube',
    'curl',
    'cve-tou',
    'D-FSL-1.0',
    'DEC-3-Clause',
    'diffmark',
    'DL-DE-BY-2.0',
    'DL-DE-ZERO-2.0',
    'DOC',
    'Dotseqn',
    'DRL-1.0',
    'DRL-1.1',
    'DSDP',
    'dtoa',
    'dvipdfm',
    'ECL-1.0',
    'ECL-2.0',
    'eCos-2.0',
    'EFL-1.0',
    'EFL-2.0',
    'eGenix',
    'Elastic-2.0',
    'Entessa',
    'EPICS',
    'EPL-1.0',
    'EPL-2.0',
    'ErlPL-1.1',
    'etalab-2.0',
    'EUDatagrid',
    'EUPL-1.0',
    'EUPL-1.1',
    'EUPL-1.2',
    'Eurosym',
    'Fair',
    'FBM',
    'FDK-AAC',
    'Ferguson-Twofish',
    'Frameworx-1.0',
    'FreeBSD-DOC',
    'FreeImage',
    'FSFAP',
    'FSFAP-no-warranty-disclaimer',
    'FSFUL',
    'FSFULLR',
    'FSFULLRWD',
    'FTL',
    'Furuseth',
    'fwlw',
    'GCR-docs',
    'GD',
    'GFDL-1.1',
    'GFDL-1.1-invariants-only',
    'GFDL-1.1-invariants-or-later',
    'GFDL-1.1-no-invariants-only',
    'GFDL-1.1-no-invariants-or-later',
    'GFDL-1.1-only',
    'GFDL-1.1-or-later',
    'GFDL-1.2',
    'GFDL-1.2-invariants-only',
    'GFDL-1.2-invariants-or-later',
    'GFDL-1.2-no-invariants-only',
    'GFDL-1.2-no-invariants-or-later',
    'GFDL-1.2-only',
    'GFDL-1.2-or-later',
    'GFDL-1.3',
    'GFDL-1.3-invariants-only',
    'GFDL-1.3-invariants-or-later',
    'GFDL-1.3-no-invariants-only',
    'GFDL-1.3-no-invariants-or-later',
    'GFDL-1.3-only',
    'GFDL-1.3-or-later',
    'Giftware',
    'GL2PS',
    'Glide',
    'Glulxe',
    'GLWTPL',
    'gnuplot',
    'GPL-1.0',
    'GPL-1.0+',
    'GPL-1.0-only',
    'GPL-1.0-or-later',
    'GPL-2.0',
    'GPL-2.0+',
    'GPL-2.0-only',
    'GPL-2.0-or-later',
    'GPL-2.0-with-autoconf-exception',
    'GPL-2.0-with-bison-exception',
    'GPL-2.0-with-classpath-exception',
    'GPL-2.0-with-font-exception',
    'GPL-2.0-with-GCC-exception',
    'GPL-3.0',
    'GPL-3.0+',
    'GPL-3.0-only',
    'GPL-3.0-or-later',
    'GPL-3.0-with-autoconf-exception',
    'GPL-3.0-with-GCC-exception',
    'Graphics-Gems',
    'gSOAP-1.3b',
    'gtkbook',
    'Gutmann',
    'HaskellReport',
    'hdparm',
    'Hippocratic-2.1',
    'HP-1986',
    'HP-1989',
    'HPND',
    'HPND-DEC',
    'HPND-doc',
    'HPND-doc-sell',
    'HPND-export-US',
    'HPND-export-US-acknowledgement',
    'HPND-export-US-modify',
    'HPND-export2-US',
    'HPND-Fenneberg-Livingston',
    'HPND-INRIA-IMAG',
    'HPND-Intel',
    'HPND-Kevlin-Henney',
    'HPND-Markus-Kuhn',
    'HPND-merchantability-variant',
    'HPND-MIT-disclaimer',
    'HPND-Pbmplus',
    'HPND-sell-MIT-disclaimer-xserver',
    'HPND-sell-regexpr',
    'HPND-sell-variant',
    'HPND-sell-variant-MIT-disclaimer',
    'HPND-sell-variant-MIT-disclaimer-rev',
    'HPND-UC',
    'HPND-UC-export-US',
    'HTMLTIDY',
    'IBM-pibs',
    'ICU',
    'IEC-Code-Components-EULA',
    'IJG',
    'IJG-short',
    'ImageMagick',
    'iMatix',
    'Imlib2',
    'Info-ZIP',
    'Inner-Net-2.0',
    'Intel',
    'Intel-ACPI',
    'Interbase-1.0',
    'IPA',
    'IPL-1.0',
    'ISC',
    'ISC-Veillard',
    'Jam',
    'JasPer-2.0',
    'JPL-image',
    'JPNIC',
    'JSON',
    'Kastrup',
    'Kazlib',
    'Knuth-CTAN',
    'LAL-1.2',
    'LAL-1.3',
    'Latex2e',
    'Latex2e-translated-notice',
    'Leptonica',
    'LGPL-2.0',
    'LGPL-2.0+',
    'LGPL-2.0-only',
    'LGPL-2.0-or-later',
    'LGPL-2.1',
    'LGPL-2.1+',
    'LGPL-2.1-only',
    'LGPL-2.1-or-later',
    'LGPL-3.0',
    'LGPL-3.0+',
    'LGPL-3.0-only',
    'LGPL-3.0-or-later',
    'LGPLLR',
    'Libpng',
    'libpng-2.0',
    'libselinux-1.0',
    'libtiff',
    'libutil-David-Nugent',
    'LiLiQ-P-1.1',
    'LiLiQ-R-1.1',
    'LiLiQ-Rplus-1.1',
    'Linux-man-pages-1-para',
    'Linux-man-pages-copyleft',
    'Linux-man-pages-copyleft-2-para',
    'Linux-man-pages-copyleft-var',
    'Linux-OpenIB',
    'LOOP',
    'LPD-document',
    'LPL-1.0',
    'LPL-1.02',
    'LPPL-1.0',
    'LPPL-1.1',
    'LPPL-1.2',
    'LPPL-1.3a',
    'LPPL-1.3c',
    'lsof',
    'Lucida-Bitmap-Fonts',
    'LZMA-SDK-9.11-to-9.20',
    'LZMA-SDK-9.22',
    'Mackerras-3-Clause',
    'Mackerras-3-Clause-acknowledgment',
    'magaz',
    'mailprio',
    'MakeIndex',
    'Martin-Birgmeier',
    'McPhee-slideshow',
    'metamail',
    'Minpack',
    'MirOS',
    'MIT',
    'MIT-0',
    'MIT-advertising',
    'MIT-CMU',
    'MIT-enna',
    'MIT-feh',
    'MIT-Festival',
    'MIT-Khronos-old',
    'MIT-Modern-Variant',
    'MIT-open-group',
    'MIT-testregex',
    'MIT-Wu',
    'MITNFA',
    'MMIXware',
    'Motosoto',
    'MPEG-SSG',
    'mpi-permissive',
    'mpich2',
    'MPL-1.0',
    'MPL-1.1',
    'MPL-2.0',
    'MPL-2.0-no-copyleft-exception',
    'mplus',
    'MS-LPL',
    'MS-PL',
    'MS-RL',
    'MTLL',
    'MulanPSL-1.0',
    'MulanPSL-2.0',
    'Multics',
    'Mup',
    'NAIST-2003',
    'NASA-1.3',
    'Naumen',
    'NBPL-1.0',
    'NCBI-PD',
    'NCGL-UK-2.0',
    'NCL',
    'NCSA',
    'Net-SNMP',
    'NetCDF',
    'Newsletr',
    'NGPL',
    'NICTA-1.0',
    'NIST-PD',
    'NIST-PD-fallback',
    'NIST-Software',
    'NLOD-1.0',
    'NLOD-2.0',
    'NLPL',
    'Nokia',
    'NOSL',
    'Noweb',
    'NPL-1.0',
    'NPL-1.1',
    'NPOSL-3.0',
    'NRL',
    'NTP',
    'NTP-0',
    'Nunit',
    'O-UDA-1.0',
    'OAR',
    'OCCT-PL',
    'OCLC-2.0',
    'ODbL-1.0',
    'ODC-By-1.0',
    'OFFIS',
    'OFL-1.0',
    'OFL-1.0-no-RFN',
    'OFL-1.0-RFN',
    'OFL-1.1',
    'OFL-1.1-no-RFN',
    'OFL-1.1-RFN',
    'OGC-1.0',
    'OGDL-Taiwan-1.0',
    'OGL-Canada-2.0',
    'OGL-UK-1.0',
    'OGL-UK-2.0',
    'OGL-UK-3.0',
    'OGTSL',
    'OLDAP-1.1',
    'OLDAP-1.2',
    'OLDAP-1.3',
    'OLDAP-1.4',
    'OLDAP-2.0',
    'OLDAP-2.0.1',
    'OLDAP-2.1',
    'OLDAP-2.2',
    'OLDAP-2.2.1',
    'OLDAP-2.2.2',
    'OLDAP-2.3',
    'OLDAP-2.4',
    'OLDAP-2.5',
    'OLDAP-2.6',
    'OLDAP-2.7',
    'OLDAP-2.8',
    'OLFL-1.3',
    'OML',
    'OpenPBS-2.3',
    'OpenSSL',
    'OpenSSL-standalone',
    'OpenVision',
    'OPL-1.0',
    'OPL-UK-3.0',
    'OPUBL-1.0',
    'OSET-PL-2.1',
    'OSL-1.0',
    'OSL-1.1',
    'OSL-2.0',
    'OSL-2.1',
    'OSL-3.0',
    'PADL',
    'Parity-6.0.0',
    'Parity-7.0.0',
    'PDDL-1.0',
    'PHP-3.0',
    'PHP-3.01',
    'Pixar',
    'pkgconf',
    'Plexus',
    'pnmstitch',
    'PolyForm-Noncommercial-1.0.0',
    'PolyForm-Small-Business-1.0.0',
    'PostgreSQL',
    'PPL',
    'PSF-2.0',
    'psfrag',
    'psutils',
    'Python-2.0',
    'Python-2.0.1',
    'python-ldap',
    'Qhull',
    'QPL-1.0',
    'QPL-1.0-INRIA-2004',
    'radvd',
    'Rdisc',
    'RHeCos-1.1',
    'RPL-1.1',
    'RPL-1.5',
    'RPSL-1.0',
    'RSA-MD',
    'RSCPL',
    'Ruby',
    'SAX-PD',
    'SAX-PD-2.0',
    'Saxpath',
    'SCEA',
    'SchemeReport',
    'Sendmail',
    'Sendmail-8.23',
    'SGI-B-1.0',
    'SGI-B-1.1',
    'SGI-B-2.0',
    'SGI-OpenGL',
    'SGP4',
    'SHL-0.5',
    'SHL-0.51',
    'SimPL-2.0',
    'SISSL',
    'SISSL-1.2',
    'SL',
    'Sleepycat',
    'SMLNJ',
    'SMPPL',
    'SNIA',
    'snprintf',
    'softSurfer',
    'Soundex',
    'Spencer-86',
    'Spencer-94',
    'Spencer-99',
    'SPL-1.0',
    'ssh-keyscan',
    'SSH-OpenSSH',
    'SSH-short',
    'SSLeay-standalone',
    'SSPL-1.0',
    'StandardML-NJ',
    'SugarCRM-1.1.3',
    'Sun-PPP',
    'Sun-PPP-2000',
    'SunPro',
    'SWL',
    'swrule',
    'Symlinks',
    'TAPR-OHL-1.0',
    'TCL',
    'TCP-wrappers',
    'TermReadKey',
    'TGPPL-1.0',
    'threeparttable',
    'TMate',
    'TORQUE-1.1',
    'TOSL',
    'TPDL',
    'TPL-1.0',
    'TTWL',
    'TTYP0',
    'TU-Berlin-1.0',
    'TU-Berlin-2.0',
    'UCAR',
    'UCL-1.0',
    'ulem',
    'UMich-Merit',
    'Unicode-3.0',
    'Unicode-DFS-2015',
    'Unicode-DFS-2016',
    'Unicode-TOU',
    'UnixCrypt',
    'Unlicense',
    'UPL-1.0',
    'URT-RLE',
    'Vim',
    'VOSTROM',
    'VSL-1.0',
    'W3C',
    'W3C-19980720',
    'W3C-20150513',
    'w3m',
    'Watcom-1.0',
    'Widget-Workshop',
    'Wsuipa',
    'WTFPL',
    'wxWindows',
    'X11',
    'X11-distribute-modifications-variant',
    'Xdebug-1.03',
    'Xerox',
    'Xfig',
    'XFree86-1.1',
    'xinetd',
    'xkeyboard-config-Zinoviev',
    'xlock',
    'Xnet',
    'xpp',
    'XSkat',
    'xzoom',
    'YPL-1.0',
    'YPL-1.1',
    'Zed',
    'Zeeff',
    'Zend-2.0',
    'Zimbra-1.3',
    'Zimbra-1.4',
    'Zlib',
    'zlib-acknowledgement',
    'ZPL-1.1',
    'ZPL-2.0',
    'ZPL-2.1');
  SPDXExceptionIdentifiers: array[0..69] of string = (
    '389-exception',
    'Asterisk-exception',
    'Asterisk-linking-protocols-exception',
    'Autoconf-exception-2.0',
    'Autoconf-exception-3.0',
    'Autoconf-exception-generic',
    'Autoconf-exception-generic-3.0',
    'Autoconf-exception-macro',
    'Bison-exception-1.24',
    'Bison-exception-2.2',
    'Bootloader-exception',
    'Classpath-exception-2.0',
    'CLISP-exception-2.0',
    'cryptsetup-OpenSSL-exception',
    'DigiRule-FOSS-exception',
    'eCos-exception-2.0',
    'Fawkes-Runtime-exception',
    'FLTK-exception',
    'fmt-exception',
    'Font-exception-2.0',
    'freertos-exception-2.0',
    'GCC-exception-2.0',
    'GCC-exception-2.0-note',
    'GCC-exception-3.1',
    'Gmsh-exception',
    'GNAT-exception',
    'GNOME-examples-exception',
    'GNU-compiler-exception',
    'gnu-javamail-exception',
    'GPL-3.0-interface-exception',
    'GPL-3.0-linking-exception',
    'GPL-3.0-linking-source-exception',
    'GPL-CC-1.0',
    'GStreamer-exception-2005',
    'GStreamer-exception-2008',
    'i2p-gpl-java-exception',
    'KiCad-libraries-exception',
    'LGPL-3.0-linking-exception',
    'libpri-OpenH323-exception',
    'Libtool-exception',
    'Linux-syscall-note',
    'LLGPL',
    'LLVM-exception',
    'LZMA-exception',
    'mif-exception',
    'Nokia-Qt-exception-1.1',
    'OCaml-LGPL-linking-exception',
    'OCCT-exception-1.0',
    'OpenJDK-assembly-exception-1.0',
    'openvpn-openssl-exception',
    'PCRE2-exception',
    'PS-or-PDF-font-exception-20170817',
    'QPL-1.0-INRIA-2004-exception',
    'Qt-GPL-exception-1.0',
    'Qt-LGPL-exception-1.1',
    'Qwt-exception-1.0',
    'RRDtool-FLOSS-exception-2.0',
    'SANE-exception',
    'SHL-2.0',
    'SHL-2.1',
    'stunnel-exception',
    'SWI-exception',
    'Swift-exception',
    'Texinfo-exception',
    'u-boot-exception-2.0',
    'UBDL-exception',
    'Universal-FOSS-exception-1.0',
    'vsftpd-openssl-exception',
    'WxWindows-exception-3.1',
    'x11vnc-openssl-exception');

type
  TSPDXTokenKind = (stkInvalid, stkEnd, stkIdentifier, stkAnd, stkOr,
    stkWith, stkLeftParenthesis, stkRightParenthesis, stkPlus);

  TSPDXExpressionParser = class
  private
    FText: string;
    FPosition: Integer;
    FTokenCount: Integer;
    FDepth: Integer;
    FTokenKind: TSPDXTokenKind;
    FTokenText: string;
    FTokenHadLeadingSpace: Boolean;
    procedure NextToken;
    function ParsePrimary(out AAllowsWith: Boolean): Boolean;
    function ParseWithExpression: Boolean;
    function ParseAndExpression: Boolean;
    function ParseOrExpression: Boolean;
  public
    {**
      Creates a bounded parser over immutable expression text.

      Parameters
      ----------
      AText
        Candidate SPDX expression.

      Returns
      -------
      TSPDXExpressionParser
        Parser ready to validate the complete input.

      Raises
      ------
      None
    }
    constructor Create(const AText: string);

    {**
      Validates the complete expression and rejects trailing tokens.

      Parameters
      ----------
      None

      Returns
      -------
      Boolean
        True when every token forms one supported expression.

      Raises
      ------
      None
    }
    function Validate: Boolean;
  end;

{**
  Reports whether a character may occur in an SPDX identifier token.

  Parameters
  ----------
  AValue
    Character to classify.

  Returns
  -------
  Boolean
    True for ASCII letters, digits, period, hyphen, or reference colon.

  Raises
  ------
  None
}
function IsIdentifierCharacter(AValue: Char): Boolean;
begin
  Result := AValue in ['A'..'Z', 'a'..'z', '0'..'9', '.', '-', ':'];
end;

{**
  Searches one pinned SPDX registry using case-sensitive equality.

  Parameters
  ----------
  AValues
    SPDX identifier array from the pinned schema snapshot.
  AValue
    Case-sensitive identifier to locate.

  Returns
  -------
  Boolean
    True when the identifier occurs exactly in the registry.

  Raises
  ------
  None
}
function RegistryContains(const AValues: array of string;
  const AValue: string): Boolean;
var
  I: Integer;
begin
  for I := Low(AValues) to High(AValues) do
    if AValues[I] = AValue then
      Exit(True);
  Result := False;
end;

{**
  Validates the identifier body used by SPDX LicenseRef and DocumentRef.

  Parameters
  ----------
  AValue
    Reference suffix after its required prefix.

  Returns
  -------
  Boolean
    True for a non-empty ASCII letter, digit, period, or hyphen sequence.

  Raises
  ------
  None
}
function IsValidReferenceSuffix(const AValue: string): Boolean;
var
  I: Integer;
begin
  Result := AValue <> '';
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if not (AValue[I] in ['A'..'Z', 'a'..'z', '0'..'9', '.', '-']) then
      Exit(False);
end;

{**
  Determines whether an identifier is a valid local or document license ref.

  Parameters
  ----------
  AValue
    Case-sensitive SPDX reference identifier.

  Returns
  -------
  Boolean
    True for ``LicenseRef-*`` or ``DocumentRef-*:LicenseRef-*`` forms.

  Raises
  ------
  None
}
function IsLicenseReference(const AValue: string): Boolean;
var
  SeparatorAt: SizeInt;
  DocumentValue, LicenseValue: string;
begin
  if Pos('LicenseRef-', AValue) = 1 then
    Exit(IsValidReferenceSuffix(Copy(AValue, Length('LicenseRef-') + 1,
      MaxInt)));
  SeparatorAt := Pos(':LicenseRef-', AValue);
  if SeparatorAt <= Length('DocumentRef-') then
    Exit(False);
  DocumentValue := Copy(AValue, 1, SeparatorAt - 1);
  LicenseValue := Copy(AValue, SeparatorAt + Length(':LicenseRef-'), MaxInt);
  Result := (Pos('DocumentRef-', DocumentValue) = 1) and
    IsValidReferenceSuffix(Copy(DocumentValue, Length('DocumentRef-') + 1,
      MaxInt)) and IsValidReferenceSuffix(LicenseValue);
end;

constructor TSPDXExpressionParser.Create(const AText: string);
begin
  inherited Create;
  FText := AText;
  FPosition := 1;
  FTokenCount := 0;
  FDepth := 0;
  FTokenKind := stkInvalid;
  FTokenText := '';
  FTokenHadLeadingSpace := False;
end;

{**
  Advances to the next bounded SPDX grammar token.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure TSPDXExpressionParser.NextToken;
const
  MaxTokenCount = 256;
var
  StartAt: Integer;
begin
  FTokenText := '';
  FTokenHadLeadingSpace := False;
  while (FPosition <= Length(FText)) and (FText[FPosition] = ' ') do
  begin
    FTokenHadLeadingSpace := True;
    Inc(FPosition);
  end;
  if FPosition > Length(FText) then
  begin
    FTokenKind := stkEnd;
    Exit;
  end;
  Inc(FTokenCount);
  if FTokenCount > MaxTokenCount then
  begin
    FTokenKind := stkInvalid;
    Exit;
  end;
  case FText[FPosition] of
    '(':
      begin
        FTokenKind := stkLeftParenthesis;
        Inc(FPosition);
        Exit;
      end;
    ')':
      begin
        FTokenKind := stkRightParenthesis;
        Inc(FPosition);
        Exit;
      end;
    '+':
      begin
        FTokenKind := stkPlus;
        Inc(FPosition);
        Exit;
      end;
  end;
  if not IsIdentifierCharacter(FText[FPosition]) then
  begin
    FTokenKind := stkInvalid;
    Inc(FPosition);
    Exit;
  end;
  StartAt := FPosition;
  while (FPosition <= Length(FText)) and
    IsIdentifierCharacter(FText[FPosition]) do
    Inc(FPosition);
  FTokenText := Copy(FText, StartAt, FPosition - StartAt);
  if FTokenText = 'AND' then
    FTokenKind := stkAnd
  else if FTokenText = 'OR' then
    FTokenKind := stkOr
  else if FTokenText = 'WITH' then
    FTokenKind := stkWith
  else
    FTokenKind := stkIdentifier;
end;

{**
  Parses one SPDX identifier, reference, or parenthesized subexpression.

  Parameters
  ----------
  AAllowsWith
    Receives whether the parsed primary may be followed by ``WITH``.

  Returns
  -------
  Boolean
    True when a complete bounded primary expression was consumed.

  Raises
  ------
  None
}
function TSPDXExpressionParser.ParsePrimary(out AAllowsWith: Boolean): Boolean;
const
  MaxNestingDepth = 32;
var
  HasAdjacentPlus, WasReference: Boolean;
begin
  AAllowsWith := False;
  if FTokenKind = stkIdentifier then
  begin
    WasReference := IsLicenseReference(FTokenText);
    Result := RegistryContains(SPDXLicenseIdentifiers, FTokenText) or
      WasReference;
    if not Result then
      Exit;
    AAllowsWith := not WasReference;
    HasAdjacentPlus := (FPosition <= Length(FText)) and
      (FText[FPosition] = '+');
    NextToken;
    if FTokenKind = stkPlus then
    begin
      if WasReference or not HasAdjacentPlus then
        Exit(False);
      NextToken;
    end;
    Exit(True);
  end;
  if FTokenKind <> stkLeftParenthesis then
    Exit(False);
  Inc(FDepth);
  if FDepth > MaxNestingDepth then
    Exit(False);
  NextToken;
  Result := ParseOrExpression and (FTokenKind = stkRightParenthesis);
  if Result then
    NextToken;
  Dec(FDepth);
end;

{**
  Parses a primary expression with an optional registered SPDX exception.

  Parameters
  ----------
  None

  Returns
  -------
  Boolean
    True when the primary and any ``WITH`` clause are valid and consumed.

  Raises
  ------
  None
}
function TSPDXExpressionParser.ParseWithExpression: Boolean;
var
  AllowsWith, HasTrailingSpace: Boolean;
begin
  Result := ParsePrimary(AllowsWith);
  if not Result or (FTokenKind <> stkWith) then
    Exit;
  if not AllowsWith or not FTokenHadLeadingSpace then
    Exit(False);
  HasTrailingSpace := (FPosition <= Length(FText)) and
    (FText[FPosition] = ' ');
  NextToken;
  Result := HasTrailingSpace and (FTokenKind = stkIdentifier) and
    RegistryContains(SPDXExceptionIdentifiers, FTokenText);
  if Result then
    NextToken;
end;

{**
  Parses a left-associative sequence of SPDX ``AND`` expressions.

  Parameters
  ----------
  None

  Returns
  -------
  Boolean
    True when every conjunction operand is valid and consumed.

  Raises
  ------
  None
}
function TSPDXExpressionParser.ParseAndExpression: Boolean;
var
  HasTrailingSpace: Boolean;
begin
  Result := ParseWithExpression;
  while Result and (FTokenKind = stkAnd) do
  begin
    if not FTokenHadLeadingSpace then
      Exit(False);
    HasTrailingSpace := (FPosition <= Length(FText)) and
      (FText[FPosition] = ' ');
    NextToken;
    Result := HasTrailingSpace and ParseWithExpression;
  end;
end;

{**
  Parses a left-associative sequence of SPDX ``OR`` expressions.

  Parameters
  ----------
  None

  Returns
  -------
  Boolean
    True when every disjunction operand is valid and consumed.

  Raises
  ------
  None
}
function TSPDXExpressionParser.ParseOrExpression: Boolean;
var
  HasTrailingSpace: Boolean;
begin
  Result := ParseAndExpression;
  while Result and (FTokenKind = stkOr) do
  begin
    if not FTokenHadLeadingSpace then
      Exit(False);
    HasTrailingSpace := (FPosition <= Length(FText)) and
      (FText[FPosition] = ' ');
    NextToken;
    Result := HasTrailingSpace and ParseAndExpression;
  end;
end;

function TSPDXExpressionParser.Validate: Boolean;
begin
  NextToken;
  Result := ParseOrExpression and (FTokenKind = stkEnd);
end;

function IsValidSPDXExpression(const AValue: string): Boolean;
const
  MaxExpressionLength = 4096;
var
  I: Integer;
  Parser: TSPDXExpressionParser;
  ValueText: string;
begin
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) < 32) or (Ord(AValue[I]) = 127) then
      Exit(False);
  ValueText := Trim(AValue);
  if (ValueText = '') or (Length(ValueText) > MaxExpressionLength) then
    Exit(False);
  Parser := TSPDXExpressionParser.Create(ValueText);
  try
    Result := Parser.Validate;
  finally
    Parser.Free;
  end;
end;

end.
