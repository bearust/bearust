import React from 'react'; import {createRoot} from 'react-dom/client'; import './styles.css'; import App from './App';
import { I18nextProvider } from 'react-i18next';
import { i18n, initI18n } from './i18n';
import { ThemeProvider, bootstrapTheme } from './theme';

bootstrapTheme();
void initI18n();
createRoot(document.getElementById('root')!).render(<React.StrictMode><I18nextProvider i18n={i18n}><ThemeProvider><App/></ThemeProvider></I18nextProvider></React.StrictMode>);
