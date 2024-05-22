# -*- buffer-read-only: t -*-
# !!!!!!!   DO NOT EDIT THIS FILE   !!!!!!!
# This file is built by regen/warnings.pl.
# Any changes made here will be lost!

package warnings;

our $VERSION = "1.47";

# Verify that we're called correctly so that warnings will work.
# Can't use Carp, since Carp uses us!
# String regexps because constant folding = smaller optree = less memory vs regexp literal
# see also strict.pm.
die sprintf "Incorrect use of pragma '%s' at %s line %d.\n", __PACKAGE__, +(caller)[1,2]
    if __FILE__ !~ ( '(?x) \b     '.__PACKAGE__.'  \.pmc? \z' )
    && __FILE__ =~ ( '(?x) \b (?i:'.__PACKAGE__.') \.pmc? \z' );

our %Offsets = (
    # Warnings Categories added in Perl 5.008
    'all'				=> 0,
    'closure'				=> 2,
    'deprecated'			=> 4,
    'exiting'				=> 6,
    'glob'				=> 8,
    'io'				=> 10,
    'closed'				=> 12,
    'exec'				=> 14,
    'layer'				=> 16,
    'newline'				=> 18,
    'pipe'				=> 20,
    'unopened'				=> 22,
    'misc'				=> 24,
    'numeric'				=> 26,
    'once'				=> 28,
    'overflow'				=> 30,
    'pack'				=> 32,
    'portable'				=> 34,
    'recursion'				=> 36,
    'redefine'				=> 38,
    'regexp'				=> 40,
    'severe'				=> 42,
    'debugging'				=> 44,
    'inplace'				=> 46,
    'internal'				=> 48,
    'malloc'				=> 50,
    'signal'				=> 52,
    'substr'				=> 54,
    'syntax'				=> 56,
    'ambiguous'				=> 58,
    'bareword'				=> 60,
    'digit'				=> 62,
    'parenthesis'			=> 64,
    'precedence'			=> 66,
    'printf'				=> 68,
    'prototype'				=> 70,
    'qw'				=> 72,
    'reserved'				=> 74,
    'semicolon'				=> 76,
    'taint'				=> 78,
    'threads'				=> 80,
    'uninitialized'			=> 82,
    'unpack'				=> 84,
    'untie'				=> 86,
    'utf8'				=> 88,
    'void'				=> 90,

    # Warnings Categories added in Perl 5.011
    'imprecision'			=> 92,
    'illegalproto'			=> 94,

    # Warnings Categories added in Perl 5.013
    'non_unicode'			=> 96,
    'nonchar'				=> 98,
    'surrogate'				=> 100,

    # Warnings Categories added in Perl 5.017
    'experimental'			=> 102,
    'experimental::lexical_subs'	=> 104,
    'experimental::regex_sets'		=> 106,
    'experimental::smartmatch'		=> 108,

    # Warnings Categories added in Perl 5.019
    'experimental::postderef'		=> 110,
    'experimental::signatures'		=> 112,
    'syscalls'				=> 114,

    # Warnings Categories added in Perl 5.021
    'experimental::bitwise'		=> 116,
    'experimental::const_attr'		=> 118,
    'experimental::re_strict'		=> 120,
    'experimental::refaliasing'		=> 122,
    'experimental::win32_perlio'	=> 124,
    'locale'				=> 126,
    'missing'				=> 128,
    'redundant'				=> 130,

    # Warnings Categories added in Perl 5.025
    'experimental::declared_refs'	=> 132,

    # Warnings Categories added in Perl 5.027
    'experimental::alpha_assertions'	=> 134,
    'experimental::script_run'		=> 136,
    'shadow'				=> 138,

    # Warnings Categories added in Perl 5.029
    'experimental::private_use'		=> 140,
    'experimental::uniprop_wildcards'	=> 142,
    'experimental::vlb'			=> 144,

    # Warnings Categories added in Perl 5.031
    'experimental::isa'			=> 146,
);

our %Bits = (
    'all'				=> "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55", # [0..75]
    'ambiguous'				=> "\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [29]
    'bareword'				=> "\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [30]
    'closed'				=> "\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [6]
    'closure'				=> "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [1]
    'debugging'				=> "\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [22]
    'deprecated'			=> "\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [2]
    'digit'				=> "\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [31]
    'exec'				=> "\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [7]
    'exiting'				=> "\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [3]
    'experimental'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x55\x51\x15\x50\x51\x05", # [51..56,58..62,66..68,70..73]
    'experimental::alpha_assertions'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00", # [67]
    'experimental::bitwise'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00", # [58]
    'experimental::const_attr'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00", # [59]
    'experimental::declared_refs'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00", # [66]
    'experimental::isa'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04", # [73]
    'experimental::lexical_subs'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00", # [52]
    'experimental::postderef'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00", # [55]
    'experimental::private_use'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00", # [70]
    'experimental::re_strict'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00", # [60]
    'experimental::refaliasing'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00", # [61]
    'experimental::regex_sets'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00", # [53]
    'experimental::script_run'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00", # [68]
    'experimental::signatures'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", # [56]
    'experimental::smartmatch'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00", # [54]
    'experimental::uniprop_wildcards'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00", # [71]
    'experimental::vlb'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", # [72]
    'experimental::win32_perlio'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00", # [62]
    'glob'				=> "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [4]
    'illegalproto'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00", # [47]
    'imprecision'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00", # [46]
    'inplace'				=> "\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [23]
    'internal'				=> "\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [24]
    'io'				=> "\x00\x54\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00", # [5..11,57]
    'layer'				=> "\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [8]
    'locale'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00", # [63]
    'malloc'				=> "\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [25]
    'misc'				=> "\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [12]
    'missing'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00", # [64]
    'newline'				=> "\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [9]
    'non_unicode'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00", # [48]
    'nonchar'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00", # [49]
    'numeric'				=> "\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [13]
    'once'				=> "\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [14]
    'overflow'				=> "\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [15]
    'pack'				=> "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [16]
    'parenthesis'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [32]
    'pipe'				=> "\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [10]
    'portable'				=> "\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [17]
    'precedence'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [33]
    'printf'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [34]
    'prototype'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [35]
    'qw'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [36]
    'recursion'				=> "\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [18]
    'redefine'				=> "\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [19]
    'redundant'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00", # [65]
    'regexp'				=> "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [20]
    'reserved'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [37]
    'semicolon'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [38]
    'severe'				=> "\x00\x00\x00\x00\x00\x54\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [21..25]
    'shadow'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00", # [69]
    'signal'				=> "\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [26]
    'substr'				=> "\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [27]
    'surrogate'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00", # [50]
    'syntax'				=> "\x00\x00\x00\x00\x00\x00\x00\x55\x55\x15\x00\x40\x00\x00\x00\x00\x00\x00\x00", # [28..38,47]
    'syscalls'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00", # [57]
    'taint'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [39]
    'threads'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00", # [40]
    'uninitialized'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00", # [41]
    'unopened'				=> "\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [11]
    'unpack'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00", # [42]
    'untie'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00", # [43]
    'utf8'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x15\x00\x00\x00\x00\x00\x00", # [44,48..50]
    'void'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00", # [45]
);

our %DeadBits = (
    'all'				=> "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", # [0..75]
    'ambiguous'				=> "\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [29]
    'bareword'				=> "\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [30]
    'closed'				=> "\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [6]
    'closure'				=> "\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [1]
    'debugging'				=> "\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [22]
    'deprecated'			=> "\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [2]
    'digit'				=> "\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [31]
    'exec'				=> "\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [7]
    'exiting'				=> "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [3]
    'experimental'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xaa\xa2\x2a\xa0\xa2\x0a", # [51..56,58..62,66..68,70..73]
    'experimental::alpha_assertions'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00", # [67]
    'experimental::bitwise'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00", # [58]
    'experimental::const_attr'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00", # [59]
    'experimental::declared_refs'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00", # [66]
    'experimental::isa'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08", # [73]
    'experimental::lexical_subs'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00", # [52]
    'experimental::postderef'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00", # [55]
    'experimental::private_use'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00", # [70]
    'experimental::re_strict'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00", # [60]
    'experimental::refaliasing'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00", # [61]
    'experimental::regex_sets'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00", # [53]
    'experimental::script_run'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00", # [68]
    'experimental::signatures'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00", # [56]
    'experimental::smartmatch'		=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00", # [54]
    'experimental::uniprop_wildcards'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00", # [71]
    'experimental::vlb'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", # [72]
    'experimental::win32_perlio'	=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00", # [62]
    'glob'				=> "\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [4]
    'illegalproto'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00", # [47]
    'imprecision'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00", # [46]
    'inplace'				=> "\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [23]
    'internal'				=> "\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [24]
    'io'				=> "\x00\xa8\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00", # [5..11,57]
    'layer'				=> "\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [8]
    'locale'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00", # [63]
    'malloc'				=> "\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [25]
    'misc'				=> "\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [12]
    'missing'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00", # [64]
    'newline'				=> "\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [9]
    'non_unicode'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00", # [48]
    'nonchar'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00", # [49]
    'numeric'				=> "\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [13]
    'once'				=> "\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [14]
    'overflow'				=> "\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [15]
    'pack'				=> "\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [16]
    'parenthesis'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [32]
    'pipe'				=> "\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [10]
    'portable'				=> "\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [17]
    'precedence'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [33]
    'printf'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [34]
    'prototype'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [35]
    'qw'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [36]
    'recursion'				=> "\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [18]
    'redefine'				=> "\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [19]
    'redundant'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00", # [65]
    'regexp'				=> "\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [20]
    'reserved'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [37]
    'semicolon'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [38]
    'severe'				=> "\x00\x00\x00\x00\x00\xa8\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [21..25]
    'shadow'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00", # [69]
    'signal'				=> "\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [26]
    'substr'				=> "\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [27]
    'surrogate'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00", # [50]
    'syntax'				=> "\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\x2a\x00\x80\x00\x00\x00\x00\x00\x00\x00", # [28..38,47]
    'syscalls'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00", # [57]
    'taint'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [39]
    'threads'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00", # [40]
    'uninitialized'			=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00", # [41]
    'unopened'				=> "\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # [11]
    'unpack'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00", # [42]
    'untie'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00", # [43]
    'utf8'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x2a\x00\x00\x00\x00\x00\x00", # [44,48..50]
    'void'				=> "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00", # [45]
);

# These are used by various things, including our own tests
our $NONE				=  "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
our $DEFAULT				=  "\x10\x01\x00\x00\x00\x50\x04\x00\x00\x00\x00\x00\x00\x55\x51\x55\x50\x51\x05", # [2,4,22,23,25,52..56,58..63,66..68,70..73]
our $LAST_BIT				=  148 ;
our $BYTES				=  19 ;

sub Croaker
{
    require Carp; # this initializes %CarpInternal
    local $Carp::CarpInternal{'warnings'};
    delete $Carp::CarpInternal{'warnings'};
    Carp::croak(@_);
}

sub _expand_bits {
    my $bits = shift;
    my $want_len = ($LAST_BIT + 7) >> 3;
    my $len = length($bits);
    if ($len != $want_len) {
	if ($bits eq "") {
	    $bits = "\x00" x $want_len;
	} elsif ($len > $want_len) {
	    substr $bits, $want_len, $len-$want_len, "";
	} else {
	    my $a = vec($bits, $Offsets{all} >> 1, 2);
	    $a |= $a << 2;
	    $a |= $a << 4;
	    $bits .= chr($a) x ($want_len - $len);
	}
    }
    return $bits;
}

sub _bits {
    my $mask = shift ;
    my $catmask ;
    my $fatal = 0 ;
    my $no_fatal = 0 ;

    $mask = _expand_bits($mask);
    foreach my $word ( @_ ) {
	if ($word eq 'FATAL') {
	    $fatal = 1;
	    $no_fatal = 0;
	}
	elsif ($word eq 'NONFATAL') {
	    $fatal = 0;
	    $no_fatal = 1;
	}
	elsif ($catmask = $Bits{$word}) {
	    $mask |= $catmask ;
	    $mask |= $DeadBits{$word} if $fatal ;
	    $mask = ~(~$mask | $DeadBits{$word}) if $no_fatal ;
	}
	else
	  { Croaker("Unknown warnings category '$word'")}
    }

    return $mask ;
}

sub bits
{
    # called from B::Deparse.pm
    push @_, 'all' unless @_ ;
    return _bits("", @_) ;
}

sub import
{
    shift;

    my $mask = ${^WARNING_BITS} // ($^W ? $Bits{all} : $DEFAULT) ;

    # append 'all' when implied (empty import list or after a lone
    # "FATAL" or "NONFATAL")
    push @_, 'all'
	if !@_ || (@_==1 && ($_[0] eq 'FATAL' || $_[0] eq 'NONFATAL'));

    ${^WARNING_BITS} = _bits($mask, @_);
}

sub unimport
{
    shift;

    my $catmask ;
    my $mask = ${^WARNING_BITS} // ($^W ? $Bits{all} : $DEFAULT) ;

    # append 'all' when implied (empty import list or after a lone "FATAL")
    push @_, 'all' if !@_ || @_==1 && $_[0] eq 'FATAL';

    $mask = _expand_bits($mask);
    foreach my $word ( @_ ) {
	if ($word eq 'FATAL') {
	    next;
	}
	elsif ($catmask = $Bits{$word}) {
	    $mask = ~(~$mask | $catmask | $DeadBits{$word});
	}
	else
	  { Croaker("Unknown warnings category '$word'")}
    }

    ${^WARNING_BITS} = $mask ;
}

my %builtin_type; @builtin_type{qw(SCALAR ARRAY HASH CODE REF GLOB LVALUE Regexp)} = ();

sub LEVEL () { 8 };
sub MESSAGE () { 4 };
sub FATAL () { 2 };
sub NORMAL () { 1 };

sub __chk
{
    my $category ;
    my $offset ;
    my $isobj = 0 ;
    my $wanted = shift;
    my $has_message = $wanted & MESSAGE;
    my $has_level   = $wanted & LEVEL  ;

    if ($has_level) {
	if (@_ != ($has_message ? 3 : 2)) {
	    my $sub = (caller 1)[3];
	    my $syntax = $has_message
		? "category, level, 'message'"
		: 'category, level';
	    Croaker("Usage: $sub($syntax)");
        }
    }
    elsif (not @_ == 1 || @_ == ($has_message ? 2 : 0)) {
	my $sub = (caller 1)[3];
	my $syntax = $has_message ? "[category,] 'message'" : '[category]';
	Croaker("Usage: $sub($syntax)");
    }

    my $message = pop if $has_message;

    if (@_) {
	# check the category supplied.
	$category = shift ;
	if (my $type = ref $category) {
	    Croaker("not an object")
		if exists $builtin_type{$type};
	    $category = $type;
	    $isobj = 1 ;
	}
	$offset = $Offsets{$category};
	Croaker("Unknown warnings category '$category'")
	    unless defined $offset;
    }
    else {
	$category = (caller(1))[0] ;
	$offset = $Offsets{$category};
	Croaker("package '$category' not registered for warnings")
	    unless defined $offset ;
    }

    my $i;

    if ($isobj) {
	my $pkg;
	$i = 2;
	while (do { { package DB; $pkg = (caller($i++))[0] } } ) {
	    last unless @DB::args && $DB::args[0] =~ /^$category=/ ;
	}
	$i -= 2 ;
    }
    elsif ($has_level) {
	$i = 2 + shift;
    }
    else {
	$i = _error_loc(); # see where Carp will allocate the error
    }

    # Default to 0 if caller returns nothing.  Default to $DEFAULT if it
    # explicitly returns undef.
    my(@callers_bitmask) = (caller($i))[9] ;
    my $callers_bitmask =
	 @callers_bitmask ? $callers_bitmask[0] // $DEFAULT : 0 ;
    length($callers_bitmask) > ($offset >> 3) or $offset = $Offsets{all};

    my @results;
    foreach my $type (FATAL, NORMAL) {
	next unless $wanted & $type;

	push @results, vec($callers_bitmask, $offset + $type - 1, 1);
    }

    # &enabled and &fatal_enabled
    return $results[0] unless $has_message;

    # &warnif, and the category is neither enabled as warning nor as fatal
    return if ($wanted & (NORMAL | FATAL | MESSAGE))
		      == (NORMAL | FATAL | MESSAGE)
	&& !($results[0] || $results[1]);

    # If we have an explicit level, bypass Carp.
    if ($has_level and @callers_bitmask) {
	# logic copied from util.c:mess_sv
	my $stuff = " at " . join " line ", (caller $i)[1,2];
	$stuff .= sprintf ", <%s> %s %d",
			   *${^LAST_FH}{NAME},
			   ($/ eq "\n" ? "line" : "chunk"), $.
	    if $. && ${^LAST_FH};
	die "$message$stuff.\n" if $results[0];
	return warn "$message$stuff.\n";
    }

    require Carp;
    Carp::croak($message) if $results[0];
    # will always get here for &warn. will only get here for &warnif if the
    # category is enabled
    Carp::carp($message);
}

sub _mkMask
{
    my ($bit) = @_;
    my $mask = "";

    vec($mask, $bit, 1) = 1;
    return $mask;
}

sub register_categories
{
    my @names = @_;

    for my $name (@names) {
	if (! defined $Bits{$name}) {
	    $Offsets{$name}  = $LAST_BIT;
	    $Bits{$name}     = _mkMask($LAST_BIT++);
	    $DeadBits{$name} = _mkMask($LAST_BIT++);
	    if (length($Bits{$name}) > length($Bits{all})) {
		$Bits{all} .= "\x55";
		$DeadBits{all} .= "\xaa";
	    }
	}
    }
}

sub _error_loc {
    require Carp;
    goto &Carp::short_error_loc; # don't introduce another stack frame
}

sub enabled
{
    return __chk(NORMAL, @_);
}

sub fatal_enabled
{
    return __chk(FATAL, @_);
}

sub warn
{
    return __chk(FATAL | MESSAGE, @_);
}

sub warnif
{
    return __chk(NORMAL | FATAL | MESSAGE, @_);
}

sub enabled_at_level
{
    return __chk(NORMAL | LEVEL, @_);
}

sub fatal_enabled_at_level
{
    return __chk(FATAL | LEVEL, @_);
}

sub warn_at_level
{
    return __chk(FATAL | MESSAGE | LEVEL, @_);
}

sub warnif_at_level
{
    return __chk(NORMAL | FATAL | MESSAGE | LEVEL, @_);
}

# These are not part of any public interface, so we can delete them to save
# space.
delete @warnings::{qw(NORMAL FATAL MESSAGE LEVEL)};

1;
__END__

# ex: set ro:
