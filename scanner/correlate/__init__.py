"""Correlate module — attack-path graph and structural analysis (C1, C2)."""

from scanner.correlate.graph import AttackEdge, AttackGraph, build_attack_graph
from scanner.correlate.segmap import SegmentMap, build_segment_map

__all__ = ["AttackEdge", "AttackGraph", "SegmentMap", "build_attack_graph", "build_segment_map"]
