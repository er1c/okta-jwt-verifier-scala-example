
val v = new {
  lazy val scalaTestVersion =  "3.2.9"
}

ThisBuild / scalaVersion     := "2.13.7"
ThisBuild / version          := "0.1.0-SNAPSHOT"
ThisBuild / organization     := "com.example"
ThisBuild / organizationName := "example"

lazy val root = (project in file("."))
  .settings(
    name := "okta-jwt-verifier-scala-example",
    libraryDependencies ++= Seq(
      "com.okta.jwt" % "okta-jwt-verifier" % "0.5.1",
      "com.okta.jwt" % "okta-jwt-verifier-impl" % "0.5.1" % "runtime,test",

      // Note: ideally, these should be transitive dependencies
      "io.jsonwebtoken" % "jjwt-api" % "0.11.2", // % "runtime,test",
      "io.jsonwebtoken" % "jjwt-impl" % "0.11.2", //% "runtime,test",

      "com.squareup.okhttp3" % "mockwebserver" % "4.9.3" % Test,
      "org.scalatest" %% "scalatest" % v.scalaTestVersion % Test,
      "com.typesafe.play" %% "play-json" % "2.8.2" % Test,
    )
  )
