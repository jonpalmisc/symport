#!/bin/sh -e

PLUGIN_DIR="$HOME/Library/Application Support/Binary Ninja/plugins"

rm -fr "$PLUGIN_DIR/symport"
rm -fr "$PLUGIN_DIR/symport_binja.py"

ln -s `pwd`/symport "$PLUGIN_DIR"
ln -s `pwd`/symport_binja.py "$PLUGIN_DIR"
