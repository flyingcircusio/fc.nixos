{ pkgs, stdenv, lib, fetchurl, nixosTests }:

stdenv.mkDerivation rec {
  pname = "jitsi-meet";
  version = "1.0.4900";

  src = fetchurl {
    url = "https://download.jitsi.org/jitsi-meet/src/jitsi-meet-${version}.tar.bz2";
    sha256 = "1z3bb8ln38jk6jkgis31c39pn6jqcb6jfhgy6kgdvhasx8r9bh9d";
  };

  dontBuild = true;

  installPhase = ''
    mkdir $out
    mv * $out/
  '';

  passthru.tests = {
    single-host-smoke-test = nixosTests.jitsi-meet;
  };

  meta = with lib; {
    description = "Secure, Simple and Scalable Video Conferences";
    longDescription = ''
      Jitsi Meet is an open-source (Apache) WebRTC JavaScript application that uses Jitsi Videobridge
      to provide high quality, secure and scalable video conferences.
    '';
    homepage = "https://github.com/jitsi/jitsi-meet";
    license = licenses.asl20;
    maintainers = with maintainers; [ ];
    platforms = platforms.all;
  };
}
