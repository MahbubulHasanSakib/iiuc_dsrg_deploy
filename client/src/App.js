import React from "react";
import 'bootstrap/dist/css/bootstrap.min.css';
import './styles.css'
import {
  BrowserRouter,
  Routes,
  Route,
} from "react-router-dom";
import AboutScreen from "./screens/AboutScreen";
import ExecutiveScreen from "./screens/ExecutiveScreen";
import HomeScreen from "./screens/HomeScreen";
import PublicationScreen from "./screens/PublicationScreen";
import MembersScreen from "./screens/MembersScreen";
import MemberDetailsScreen from "./screens/MemberDetailsScreen";
import ScrollToTop from "./components/CommonComponents/ScrollToTop";
import AdminScreen from "./screens/AdminScreen";
import EditMemberScreen from "./screens/EditMemberScreen";
import LoginScreen from "./screens/LoginScreen";
import MembersListScreen from "./screens/MembersListScreen";
import ProfileScreen from "./screens/ProfileScreen";
import EventsAndNewsScreen from "./screens/EventsAndNewsScreen";
import BlogsScreen from "./screens/BlogsScreen";
function App() {
  return (
    <div className="App">
    <BrowserRouter>
    <ScrollToTop/>
    <Routes>
      <Route path="/" exact element={<HomeScreen />} />
      <Route path="/about"  element={<AboutScreen />} />
      <Route path="/founder-and-head" element={<ExecutiveScreen />} />
      <Route path="/advisory-panel" element={<ExecutiveScreen />} />
      <Route path="/teacher-trainer" element={<ExecutiveScreen />} />
      <Route path="/commitee-members" element={<ExecutiveScreen />} />
      <Route path="/publication"  element={<PublicationScreen />} />
      <Route path="/events-news"  element={<EventsAndNewsScreen />} />
      <Route path="/blogs"  element={<BlogsScreen />} />
      <Route path="/members"  element={<MembersScreen />} />
      <Route path="/me/:username"  element={<MemberDetailsScreen />} />
      <Route path="/admin"  element={<AdminScreen />} />
      <Route path="/editMember/:id"  element={<EditMemberScreen />} />
      <Route path="/login"  element={<LoginScreen />} />
      <Route path="/membersList"  element={<MembersListScreen />} />
      <Route path="/profile"  element={<ProfileScreen />} />
    </Routes>
  </BrowserRouter>
    </div>
  );
}

export default App;
