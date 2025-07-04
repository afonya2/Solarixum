import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import PrimeVue from 'primevue/config';
import Aura from '@primeuix/themes/aura'
import { definePreset } from '@primeuix/themes';
import Login from './components/Login.vue';
import Recovery from './components/Recovery.vue';
import Register from './components/Register.vue';
import { ToastService } from 'primevue';
import Terms from './components/Terms.vue';
import Showcase from './components/Showcase.vue';

const Preset = definePreset(Aura, {
    semantic: {
        primary: {
            50: '#99b2e4',
            100: '#84a2de',
            200: '#7093d9',
            300: '#5b83d3',
            400: '#4774ce',
            500: '#3264c8',
            600: '#2850a0',
            700: '#23468c',
            800: '#193264',
            900: '#0f1e3c',
            950: '#0a1428'
        },
        secondary: {
            50: '{emerald.50}',
            100: '{emerald.100}',
            200: '{emerald.200}',
            300: '{emerald.300}',
            400: '{emerald.400}',
            500: '{emerald.500}',
            600: '{emerald.600}',
            700: '{emerald.700}',
            800: '{emerald.800}',
            900: '{emerald.900}',
            950: '{emerald.950}'
        }
    }
});

let app = createApp(Login);
document.title = "Solarixum - Login";
let state = localStorage.getItem('state');
if (window.location.pathname.includes('/terms')) {
    app = createApp(Terms);
    document.title = "Solarixum - Terms of Service";
} else if (window.location.pathname == '/showcase') { //Set this to '/' when compiling
    app = createApp(Showcase);
    document.title = "Solarixum";
} else {
    if (state == "5") {
        app = createApp(App);
        app.use(ToastService)
        document.title = "Solarixum - Home";
    } else if (state == "3") {
        app = createApp(Recovery)
        document.title = "Solarixum - Recovery";
    } else if (state == "2") {
        app = createApp(Register);
        document.title = "Solarixum - Register";
    }
}

app.use(PrimeVue, {
    theme: {
        preset: Preset
    }
}).mount('#app')