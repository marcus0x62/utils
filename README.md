# utils

This repository contains small utilities I wrote for my own use; I distribute
them in the hope they may be useful to others.

* [ascii](ascii) -- ASCII Table generator.  You can pass it a single character
  as a command argument and it will just print the details for that character.
  Passing the option --in-order will show a table of values from 32 - 126 in
  order.  Passing no arguments will show the same range of characters grouped
  by type.

* [muttiml](muttiml) -- HTML Mail helper for Mutt.  This is a small Python
  script that expects to receive an email message on stdin, extracts the HTML
  message body, and performs some minimal processing to improve message
  appearance.  Finally, it saves the message to a temp file and instructs
  Safari to open the message.
  
* [vcflint](vcflint) -- Virtual Contact Format normalizer and deduplicator.
  My contacts database was overrun with duplicates and weird metadata artifacts
  that made most of my contact entries useless.  This tries to fix that by
  identifying unique contacts, searching for unique telephone and email
  addresses for each and building a de-duplicated VCF file.  This does make a
  bunch of assumptions about how I expect my contacts to look, what fields I
  care about, etc., so tread carefully and make lots of backups! Set the
  environment variable DEBUG before running for copious debug output.