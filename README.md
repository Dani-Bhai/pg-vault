# pgvault

Encrypted PostgreSQL backups from the command line.

- Streams `pg_dump` output through zstd compression and AES-256-GCM encryption; no temporary plaintext file is written.
- Stores backups locally or in S3 (including S3-compatible services such as MinIO, R2, B2 or Spaces).
- Backs up databases behind an SSH bastion and/or running inside Docker containers.
- Runs backups on a cron schedule with `pgvault daemon`.

## Install

### From GitHub (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/Dani-Bhai/pg-vault/master/install.sh | sh
```

The script downloads the release binary for your OS/architecture into `~/.local/bin` and verifies its checksum. To install somewhere else, set `BINDIR`:

```sh
curl -fsSL https://raw.githubusercontent.com/Dani-Bhai/pg-vault/master/install.sh | BINDIR=/usr/local/bin sudo sh
```

A specific version can be pinned with `VERSION`:

```sh
curl -fsSL https://raw.githubusercontent.com/Dani-Bhai/pg-vault/master/install.sh | VERSION=v0.1.0 sh
```

### From a clone

```sh
git clone https://github.com/Dani-Bhai/pg-vault
cd pg-vault
./install.sh
```

Run inside the repository, `install.sh` builds from source.

### With Go

```sh
go install github.com/Dani-Bhai/pg-vault/cmd/pgvault@latest
```

## Requirements

- PostgreSQL client tools (`pg_dump`) on the machine that runs the backup.
- Go 1.27 or newer, only for building from source. Release binaries are self-contained.
- The `docker` CLI where it is needed, only for databases with a container profile.
- SSH tunneling uses Go's SSH client; no `ssh` binary is required.

## Quick start

```sh
# Register a database.
pgvault add prod --url 'postgres://user:password@127.0.0.1:5432/prod'

# Back it up now.
pgvault backup prod

# See what is registered and what has been backed up.
pgvault databases
pgvault backups
```

Schedule recurring backups and run the scheduler in the foreground:

```sh
pgvault schedule prod "0 */6 * * *"
pgvault daemon
```

Encryption keys and settings come from the environment (for example `PGVAULT_MASTER_KEY`); storage can be local or S3. Run `pgvault help` or `pgvault help environment` for the full reference.

## Releases

Pushing a `v*` tag triggers the release workflow, which builds linux/darwin amd64/arm64 tarballs plus a `checksums.txt`:

```sh
git tag v0.1.0
git push origin v0.1.0
```

## Uninstall

```sh
rm ~/.local/bin/pgvault
```

Backup data and metadata live in `~/.pgvault` (or `$PGVAULT_DIR`).
