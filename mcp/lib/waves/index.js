"use strict";

const {
  logDeadEnds,
  WAVE_HANDOFF_CONTENT_MAX_CHARS,
  writeHandoff,
  writeWaveHandoff,
} = require("./wave-assignment-store.js");
const {
  applyWaveMerge,
} = require("./wave-merge-settler.js");
const {
  waveStatus,
} = require("./wave-prereq-snapshots.js");
const {
  startNextWave,
  startWave,
} = require("./wave-scheduler.js");
const {
  buildWaveHandoffsDocument,
  mergeWaveHandoffs,
  readWaveHandoffs,
  waveHandoffStatus,
} = require("../wave-handoff-store.js");

module.exports = {
  applyWaveMerge,
  buildWaveHandoffsDocument,
  logDeadEnds,
  mergeWaveHandoffs,
  readWaveHandoffs,
  startNextWave,
  startWave,
  waveHandoffStatus,
  waveStatus,
  writeHandoff,
  writeWaveHandoff,
  WAVE_HANDOFF_CONTENT_MAX_CHARS,
};
