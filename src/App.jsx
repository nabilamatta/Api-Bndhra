import './App.scss';
import Dashboard from './components/Dashboard/Dashboard';
import Login from './components/login/Login';
import Register from './components/register/Register';

// import  react router dom
import{
  createBrowserRouter,
  RouterProvider
} from 'react-router-dom'

// lets create a roter
const router = createBrowserRouter([
  {
    path: '/',
    element: <div><Login/></div>
  },
  {
    path: '/register',
    element: <div><Register/></div>
  },
  {
    path: '/dashboard',
    element: <div><Dashboard/></div>
  }
])

function App() {

  return (
    <>
     <div>
      <RouterProvider router={router}/>

     </div>
    </>
  )
}

export default App;
