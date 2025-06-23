# Save this as extract_lolbins.py and run it in your LOTL_test folder
import re

lolbins = set()
with open("full_lolbins_raw.txt", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if re.match(r".*\.(exe|dll|ps1|vbs|bat)$", line, re.IGNORECASE):
            lolbins.add(line.lower())

with open("all_lolbins.txt", "w", encoding="utf-8") as out:
    for bin in sorted(lolbins):
        out.write(bin + "\n")

print(f"Extracted {len(lolbins)} LOLBins to all_lolbins.txt")