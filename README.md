# Thrash

A copy-cat `hashcat` utility implemented semi-functionally.

## How to use

### Display all options
`thrash -h`

### Crack MD5 hash
`thrash -i "5d41402abc4b2a76b9719d911017c592" -m -f -p 5`

`thrash -i '$2a$04$IR8hyNGmKTE0NN1ppwgQM.aQLME.fTrMuwdx3IKQ2a.iRpulomkuG' -b -f -p 3`

## Tech Stack
- `md5`
- `bcrypt`
- `rayon` for parallel programming.