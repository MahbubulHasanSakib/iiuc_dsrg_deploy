import {
    createContext,
    ReactNode,
    useContext,
    useEffect,
    useState,
  } from "react";
  import axios from "axios";
 
  const AppContext = createContext(null);
  export function AppWrapper({ children }) {
    const [user, setUser] = useState(null);

    return (
      <AppContext.Provider value={{ userInfo: { user,setUser } }}>
        {children}
      </AppContext.Provider>
    );
  }
  
  export function useAppContext() {
    return useContext(AppContext);
  }