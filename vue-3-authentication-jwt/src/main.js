import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import store from './store';
import "bootstrap";
import "bootstrap/dist/css/bootstrap.min.css";
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome';

createApp(App).use(router).use(router).use(store).component("font-awesome-icon", FontAwesomeIcon).mount('#app')
