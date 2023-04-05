# PSNAP
**PSNAP** is an utility to create snapshots of processes for linux.

Now it supports **x86_64** only.

## Usage
* Get the id of the process to snapshot with `ps` utility.
* Then use `psnap` to make process snapshot:
    ```bash
    ./psnap --pid [pid] -o snap
    ```
    Root privileges may be required to run the `psnap` program.
* To run the snapshot use the `psnapexec` utility:
    ```bash
    ./psnapexec snap
    ```

## Build
To build `psnap` and `psnapexec` just use:
```bash
make
```
