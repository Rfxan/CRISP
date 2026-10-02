import { createContext, useContext } from 'react';

// Hide editing until the API confirms local editing is available.
export const AccessContext = createContext({ canEdit: false });
export const useAccess = () => useContext(AccessContext);
