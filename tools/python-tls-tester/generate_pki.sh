#!/bin/bash
# generate_pki.sh

if ! command -v python3 &> /dev/null
then
    echo "python3 not found."
    exit 1
fi

echo "Checking for 'cryptography' library..."
python3 -c "import cryptography" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing 'cryptography'..."
    python3 -m pip install cryptography
fi

echo "Running pki_gen.py..."
python3 pki_gen.py
if [ $? -eq 0 ]; then
    echo "PKI Generation successful!"
else
    echo "PKI Generation failed."
fi
