#!/bin/bash
# Compile translations
# Run this script after editing .po files

cd "$(dirname "$0")"

if ! command -v msgfmt &> /dev/null; then
    echo "Error: msgfmt not found. Install gettext package:"
    echo "  apt-get install gettext"
    exit 1
fi

echo "Compiling Russian translations..."
msgfmt ru.po -o ru.mo

echo "Compiling English translations..."
msgfmt en.po -o en.mo

echo "Done. Binary .mo files created."
ls -lh *.mo
