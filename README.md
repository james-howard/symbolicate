# symbolicate
A python script to symbolicate OS X (and iOS) crash logs.

Provided that you have a crash log and a dSYM file corresponding to the crashed version of the app somewhere on your system that spotlight can index, this script will process your crash log and fill out your symbols.

## Usage
`python symbolicate.py /path/to/log.crash`
