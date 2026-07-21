import React from 'react'; import {createRoot} from 'react-dom/client'; import './styles.css'; import App from './App';
import { ThemeProvider, bootstrapTheme } from './theme';

bootstrapTheme();
createRoot(document.getElementById('root')!).render(<React.StrictMode><ThemeProvider><App/></ThemeProvider></React.StrictMode>);
