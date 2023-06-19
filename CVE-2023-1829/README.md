# CVE2023-1829

The exploitation is tested on Ubuntu22.04 official source code 5.15.0-25.25 

Installing dependences for some netlink filter functions
```
sudo apt install libnftnl-dev libmnl-dev
```

Building step:
```bash
make 
```

## References 
- https://github.com/randorisec/CVE-2022-34918-LPE-PoC/tree/main