// Mirrors CrowdVault.Phase. Kept free of side effects so the seal can be rendered outside a browser.
export const Phase = { Open: 0, Locked: 1, Claimed: 2, Expired: 3 } as const;
export type PhaseValue = (typeof Phase)[keyof typeof Phase];
