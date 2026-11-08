// Symbolon: precompiled libraries are released per package version.
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:yaml/yaml.dart';

/// The release that holds the precompiled libraries of the crate in `manifestDir`:
/// `precompiled-v<version>_<crate hash>`, where the version is the Flutter package's, from the
/// pubspec.yaml next to the crate. An app that depends on a version finds that version's libraries,
/// and every release carries the version it belongs to.
String precompiledTag(String manifestDir, String crateHash) =>
    'precompiled-v${packageVersion(manifestDir)}_$crateHash';

String packageVersion(String manifestDir) {
  final file = File(path.join(manifestDir, '..', 'pubspec.yaml'));
  final version = (loadYaml(file.readAsStringSync()) as YamlMap)['version'];
  if (version is! String || !RegExp(r'^\d+\.\d+\.\d+$').hasMatch(version)) {
    throw Exception('Expected a version like 1.2.3 in ${file.path}, got $version');
  }
  return version;
}
