<?xml version="1.0" encoding="ISO-8859-15" ?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 
  <xsl:include href="util.xsl"/>
  <xsl:include href="dictionary.xsl"/>
  <xsl:include href="object.xsl"/>
  <xsl:include href="fcode.xsl"/>

  <xsl:template match="/">
   <xsl:value-of select="document('rules.xml',.)/rules/pre"/>
   <xsl:apply-templates select="." mode="dictionaries"/>
   <xsl:apply-templates select="." mode="fcode"/>
   <xsl:apply-templates select="." mode="objects"/>
  </xsl:template>
  
  <xsl:output method="text" indent="no" encoding="iso-8859-15"/>

</xsl:stylesheet>

