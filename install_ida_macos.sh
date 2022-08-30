#!/bin/sh -e

PLUGIN_DIR="$HOME/.idapro/plugins"

rm -fr "$PLUGIN_DIR/symport"
rm -fr "$PLUGIN_DIR/symport_ida.py"

ln -s `pwd`/symport $PLUGIN_DIR
ln -s `pwd`/symport_ida.py $PLUGIN_DIR
