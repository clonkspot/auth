{ pkgs ? (
    let
      inherit (builtins) fetchTree fromJSON readFile;
      inherit ((fromJSON (readFile ./flake.lock)).nodes) nixpkgs gomod2nix;
    in
    import (fetchTree nixpkgs.locked) {
      overlays = [
        (import "${fetchTree gomod2nix.locked}/overlay.nix")
      ];
    }
  )
, lib ? pkgs.lib
, buildGoApplication ? pkgs.buildGoApplication
, go

, replaceTemplates ? null
}:

buildGoApplication {
  pname = "auth";
  version = "0.1";
  pwd = ./.;
  src = ./.;
  modules = ./gomod2nix.toml;
  go = go;

  postPatch = ''
    substituteInPlace main.go \
      --replace-fail templates/pages/ "$out/templates/pages/"
  '';

  postInstall = ''
    cp -r templates "$out"
  '' + lib.optionalString (replaceTemplates != null)
    (lib.concatMapAttrsStringSep "\n"
      (tmpl: path: ''ln -sf '${path}' "$out/templates/${tmpl}"'')
      replaceTemplates);
}
