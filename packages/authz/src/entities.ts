/**
 * Cedar request/entity value types, kept deliberately small and JSON-shaped.
 * These map onto cedar-wasm's EntityUidJson / EntityJson / Context without
 * exposing the wasm types to callers.
 */

/** A Cedar entity reference: `Type::"id"`. */
export interface EntityRef {
  type: string;
  id: string;
}

/** A Cedar attribute/context value (JSON literals, entity refs, sets, records). */
export type CedarValue =
  | string
  | number
  | boolean
  | { readonly __entity: EntityRef }
  | readonly CedarValue[]
  | { readonly [key: string]: CedarValue };

/** An entity in the authorization store (its attributes + parent hierarchy). */
export interface EntityInput {
  uid: EntityRef;
  attrs?: Record<string, CedarValue>;
  parents?: readonly EntityRef[];
}

/** Wrap an entity reference as an attribute value (e.g. an asset's `owner`). */
export function ref(type: string, id: string): { readonly __entity: EntityRef } {
  return { __entity: { type, id } };
}
