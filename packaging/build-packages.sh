#!/usr/bin/env bash
# Builds the packages of the committed state (HEAD) in one run:
#
#   arch   the Arch Linux package, with makepkg on this machine
#   deb    the Debian package, in a Debian 13 container (packaging/deb/Dockerfile)
#
# Usage: packaging/build-packages.sh [arch] [deb]
#
# Without targets both are built. Everything lands in build/packages/.
#
# Environment:
#   GOVERSION    Go release to build with (default: the current one from
#                go.dev, else the local go's)
#
# Uncommitted changes are not built: the packages come from 'git archive
# HEAD', so they always match a commit.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

targets=()
for arg in "$@"; do
    case $arg in
        arch | deb) targets+=("$arg") ;;
        -h | --help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg (arch, deb)" >&2; exit 2 ;;
    esac
done
((${#targets[@]})) || targets=(arch deb)
want() { [[ " ${targets[*]} " == *" $1 "* ]]; }

die() { echo "error: $*" >&2; exit 1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "note: uncommitted changes are not in the packages (built from HEAD)"
fi

short="$(git rev-parse --short HEAD)"
gover="${GOVERSION:-$(curl -fsS --max-time 10 'https://go.dev/VERSION?m=text' 2>/dev/null | head -1 || true)}"
[[ -n "$gover" ]] || gover="$(go env GOVERSION)"
out="$root/build/packages"
mkdir -p "$out"
echo "tpm2-verifier $short, Go $gover, into build/packages/"

# Check every target's tools before building anything.
if want arch; then command -v makepkg >/dev/null || die "makepkg not found: the Arch package is built on Arch Linux (or leave out 'arch')"; fi
if want deb; then command -v docker >/dev/null || die "docker not found: the Debian package is built in a container (or leave out 'deb')"; fi

# A version for untagged trees too: 0.0.0.r<commits>.g<hash>.
describe="$(git describe --tags --long HEAD 2>/dev/null || echo "v0.0.0-$(git rev-list --count HEAD)-g$short")"

if want arch; then
    step "Arch Linux package"
    version="$(echo "$describe" | sed -e 's/^v//' -e 's/-\([0-9]\+\)-g/.r\1.g/' | tr '-' '_')"
    aur="$root/build/aur"
    mkdir -p "$aur"
    rm -rf "$aur"/tpm2-verifier-* "$aur/PKGBUILD" "$aur/src" "$aur/pkg"
    git archive --format=tar.gz --prefix="tpm2-verifier-$short/" -o "$aur/tpm2-verifier-$short.tar.gz" HEAD
    digest="$(sha256sum "$aur/tpm2-verifier-$short.tar.gz" | cut -d' ' -f1)"
    # The PKGBUILD in packaging/aur fetches the release tag; this one takes
    # the archive of HEAD instead.
    sed -e '/^_tag=/d' \
        -e "s/^pkgver=.*/pkgver=$version/" \
        -e "s/^source=.*/source=(\"tpm2-verifier-$short.tar.gz\")/" \
        -e "s/^sha256sums=.*/sha256sums=('$digest')/" \
        -e "s/^_srcdir=.*/_srcdir=\"\$pkgname-$short\"/" \
        packaging/aur/PKGBUILD > "$aur/PKGBUILD"
    (cd "$aur" && GOTOOLCHAIN="$gover" makepkg -f --nocheck)
    rm -f "$out"/tpm2-verifier-*.pkg.tar.zst
    cp "$aur"/tpm2-verifier-"$version"-*.pkg.tar.zst "$out/"
fi

if want deb; then
    step "Debian package"
    image="tpm2-verifier-deb-build:$gover"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        docker build -t "$image" --build-arg GOVER="$gover" packaging/deb
    fi
    debver="$(packaging/deb-version.sh "${describe%-0-g*}")"
    deb="$root/build/deb"
    mkdir -p "$deb"
    rm -f "$deb"/*.deb "$deb"/*.changes "$deb"/*.buildinfo "$deb"/tpm2-verifier-*.tar.gz
    git archive --format=tar.gz --prefix="tpm2-verifier-$short/" -o "$deb/tpm2-verifier-$short.tar.gz" HEAD
    # The Go build cache stays in build/deb/.gocache across runs.
    docker run --rm -v "$deb:/out" -e SHORT="$short" -e DEBVER="$debver" -e OWNER="$(id -u):$(id -g)" \
        "$image" bash -ec '
            mkdir -p /build && cd /build
            tar xzf "/out/tpm2-verifier-$SHORT.tar.gz" && cd "tpm2-verifier-$SHORT"
            sed -i "1s/^tpm2-verifier (.*)/tpm2-verifier ($DEBVER)/" debian/changelog
            DEB_BUILD_OPTIONS=nocheck GOCACHE=/out/.gocache dpkg-buildpackage -us -uc -b
            cp ../tpm2-verifier_*.deb ../*.changes ../*.buildinfo /out/
            chown -R "$OWNER" /out'
    rm -f "$out"/tpm2-verifier_*.deb
    cp "$deb"/tpm2-verifier_*.deb "$out/"
fi

step "Built"
ls -lh "$out"
