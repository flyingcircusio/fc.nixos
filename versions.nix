{ pkgs ? import <nixpkgs> {} }:

with pkgs.lib;

let
  versions = importJSON ./versions.json;

  channels =
    mapAttrs (
      name: repoInfo:
      # Hydra expects fixed length rev ids
      assert stringLength repoInfo.rev == 40;

      if repoInfo ? url then
        pkgs.fetchgit repoInfo // {
          name = "${name}-${substring 0 11 repoInfo.rev}";
        }
      else
      pkgs.fetchFromGitHub {
        inherit (repoInfo) owner repo rev sha256;
        name = "${name}-${substring 0 11 repoInfo.rev}";
      })
      versions;

  arrangeChannels =
    builtins.toFile "arrange-channels.sh" ''
      mkdir $out
      set -- ''${channels[@]}
      # 1=name 2=path
      while [[ -n "$1" && -n "$2" ]]; do
        ln -s $2 $out/"$1"
        shift 2
      done
    '';

in
assert channels ? "nixpkgs";
let
  pkgs = import channels.nixpkgs {};
in
# export "nixos-18_09" instead of "nixos-18.09" for example
(mapAttrs' (name: val: nameValuePair (replaceStrings [ "." ] [ "_" ] name) val)
  channels)
//
{
  allUpstreams = builtins.derivation {
    args = [ "-e" arrangeChannels ];
    builder = pkgs.stdenv.shell;
    channels = mapAttrsToList (name: path: "${name} ${path}") channels;
    name = "all-upstream-sources";
    PATH = with pkgs; makeBinPath [ coreutils ];
    preferLocalBuild = true;
    system = builtins.currentSystem;
  };
}
