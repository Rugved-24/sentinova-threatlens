import { geoGraticule10, geoNaturalEarth1, geoPath, type GeoPermissibleObjects } from "d3-geo";
import { useMemo, useState } from "react";
import { feature } from "topojson-client";
import worldTopology from "world-atlas/countries-110m.json";
import type { GeoData } from "../lib/types";
import { cn } from "../lib/utils";

const WIDTH = 820;
const HEIGHT = 400;

export function WorldHeatmap({ points, className }: { points: GeoData["points"]; className?: string }) {
  const [hovered, setHovered] = useState<GeoData["points"][number] | null>(null);

  const { land, projection, graticule } = useMemo(() => {
    const topology = worldTopology as unknown as Parameters<typeof feature>[0];
    const collection = feature(topology, (topology.objects as Record<string, never>).countries) as unknown as {
      type: "FeatureCollection";
      features: Array<{ type: "Feature"; properties: Record<string, unknown>; geometry: unknown }>;
    };
    const proj = geoNaturalEarth1().fitSize([WIDTH, HEIGHT], collection as unknown as GeoPermissibleObjects);
    const path = geoPath(proj);
    return {
      land: collection.features.map((item, index) => ({
        id: String(item.properties?.name ?? `region-${index}`),
        d: path(item as unknown as GeoPermissibleObjects) ?? "",
      })),
      projection: proj,
      graticule: path(geoGraticule10()) ?? "",
    };
  }, []);

  const maxCount = Math.max(...points.map((point) => point.count), 1);

  return (
    <div className={cn("relative overflow-hidden rounded-xl border border-ink-600/40 bg-ink-950/50", className)}>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="h-auto w-full" role="img" aria-label="Global indicator origin map">
        <defs>
          <radialGradient id="map-glow">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
          </radialGradient>
          <filter id="marker-glow" x="-200%" y="-200%" width="400%" height="400%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <rect width={WIDTH} height={HEIGHT} fill="#050a12" />
        <path d={graticule} fill="none" stroke="rgba(34,211,238,0.06)" strokeWidth="0.6" />
        {land.map((country) => (
          <path
            key={country.id}
            d={country.d}
            fill="rgba(20,38,61,0.62)"
            stroke="rgba(100,140,180,0.2)"
            strokeWidth="0.45"
          />
        ))}

        {points.map((point) => {
          const projected = projection([point.longitude, point.latitude]);
          if (!projected) return null;
          const [x, y] = projected;
          const radius = 3 + (point.count / maxCount) * 10;
          const color = point.critical > 0 ? "#fb7185" : point.avg_score >= 60 ? "#fbbf24" : "#22d3ee";
          return (
            <g
              key={`${point.country_code}-${point.latitude}-${point.longitude}`}
              onMouseEnter={() => setHovered(point)}
              onMouseLeave={() => setHovered(null)}
              className="cursor-pointer"
            >
              <circle cx={x} cy={y} r={radius * 2.8} fill="url(#map-glow)" opacity={0.35} />
              <circle cx={x} cy={y} r={radius} fill={color} fillOpacity={0.22} stroke={color} strokeWidth="0.8" />
              <circle cx={x} cy={y} r={1.8} fill={color} filter="url(#marker-glow)" />
            </g>
          );
        })}
      </svg>

      {hovered && (
        <div className="pointer-events-none absolute bottom-3 left-3 rounded-xl border border-ink-600/70 bg-ink-900/95 px-3 py-2 shadow-panel">
          <p className="text-xs font-medium text-white">{hovered.country_name}</p>
          <p className="mt-0.5 text-[10px] text-slate-500">
            {hovered.count} indicators · avg score {Math.round(hovered.avg_score)} · {hovered.critical} critical
          </p>
        </div>
      )}

      <div className="absolute right-3 top-3 flex items-center gap-3 rounded-lg border border-ink-600/50 bg-ink-900/80 px-2.5 py-1.5 text-[9px] uppercase tracking-[0.12em] text-slate-500">
        <span className="flex items-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full bg-rose-400" /> Critical
        </span>
        <span className="flex items-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-300" /> High
        </span>
        <span className="flex items-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full bg-cyan-300" /> Elevated
        </span>
      </div>
    </div>
  );
}
