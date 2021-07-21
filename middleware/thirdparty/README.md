# 3rd party libraries taken from elsewhere

- sha256.py:
  - Pure python3 implementation taken from https://gist.github.com/prokls/41e82472bd4968720d1482f81235e0ac
  - Originally based on: https://github.com/thomdixon/pysha2
  - Method set_midstate was added by us
  - Fixed a bug when the message size is a multiple of 64
  - Unit tested against native hashlib.sha256
