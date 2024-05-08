import { createWebHistory, createRouter } from "vue-router";
import Home from "./components/Home.vue";
import Login from "./components/Login.vue";
import Register from "./components/Register.vue";

const Profile = () => import("./components/Profile.vue");
const BoardUser = () => import("./components/BoardUser.vue");
const BoardModerator = () => import("./components/BoardModerator.vue");
const BoardAdmin = () => import("./components/BoardAdmin.vue");

const routes = [
    {
        path: "/",
        name: "Home-Page",
        component: Home,
    },
    {
        path: "/home",
        name: "Home-Page",
    },
    {
        path: "/login",
        component: Login,
    },
    {
        path: "/register",
        component: Register,
    },
    {
        path: "/profile",
        name: "Profile-Page",
        component: Profile,
    },
    {
        path: "/user",
        name: "User-Board",
        component: BoardUser,
    },
    {
        path: "/mod",
        name: "Moderator-Board",
        component: BoardModerator,
    },
    {
        path: "/admin",
        name: "Admin-Board",
        component: BoardAdmin,
    }
];

const router = createRouter({
    history: createWebHistory(),
    routes,
});

router.beforeEach((to, from, next) => {
    const publicPages = ['/login', '/register', '/home'];
    const authRequired = !publicPages.includes(to.path);
    const loggedIn = localStorage.getItem('user');
  
    // trying to access a restricted page + not logged in
    // redirect to login page
    if (authRequired && !loggedIn) {
      next('/login');
    } else {
      next();
    }
  });

export default router;