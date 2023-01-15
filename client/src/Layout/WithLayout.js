import React from "react";
import Header from "../components/CommonComponents/Header";
import Footer from "../components/CommonComponents/Footer";
const WithLayout = (PageComponent) => {
  return function WithPage({ ...props }) {
    return (
      <>
        <Header/>
        <PageComponent />
        <Footer/>
    </>
    );
  };
};

export default WithLayout;