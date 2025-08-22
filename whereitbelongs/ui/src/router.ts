import { createRouter, createWebHashHistory } from 'vue-router';

const Home = () => import('./views/Home.vue');
const Scan = () => import('./views/Scan.vue');
const Unrat = () => import('./views/Unrat.vue');
const Firewall = () => import('./views/Firewall.vue');
const Privacy = () => import('./views/Privacy.vue');
const Tools = () => import('./views/Tools.vue');
const Settings = () => import('./views/Settings.vue');
const Account = () => import('./views/Account.vue');

export default createRouter({
	history: createWebHashHistory(),
	routes: [
		{ path: '/', component: Home },
		{ path: '/scan', component: Scan },
		{ path: '/unrat', component: Unrat },
		{ path: '/firewall', component: Firewall },
		{ path: '/privacy', component: Privacy },
		{ path: '/tools', component: Tools },
		{ path: '/settings', component: Settings },
		{ path: '/account', component: Account },
	],
});