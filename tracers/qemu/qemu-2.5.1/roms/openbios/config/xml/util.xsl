<?xml version="1.0" encoding="ISO-8859-15" ?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<!-- get-dirname: get directory part of file $path-->

<!-- call me with:
  <xsl:param name="path">
   <xsl:for-each select="ancestor::build">
    <xsl:call-template name="get-dirname">
     <xsl:with-param select="@base" name="path"/>
    </xsl:call-template>
   </xsl:for-each>
  </xsl:param>
 -->						   

<xsl:template name="get-dirname">
  <xsl:param name="path"/>
  <xsl:choose>
    <xsl:when test="contains($path, '/')">
      <xsl:choose>
      <xsl:when test="substring($path, string-length($path)) != '/'">
        <xsl:call-template name="get-dirname">
          <xsl:with-param select="substring($path, 1, string-length($path)-1)" name="path"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
       <xsl:value-of select="$path"/>
      </xsl:otherwise>
      </xsl:choose>
    </xsl:when>
    <xsl:otherwise>
      <xsl:message terminate="yes">
       No valid relative path
      </xsl:message>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- return value: 0=found, 1=not found -->
<xsl:template name="resolve-condition">
  <xsl:param name="expression"/>
  <xsl:param name="confexpr">CONFIG_<xsl:value-of select="$expression"/></xsl:param>
  
  <xsl:choose>
   <xsl:when test="$expression!=''">
    <xsl:variable name="value"><xsl:value-of select="document('config.xml',.)//option[@name=$confexpr]/attribute::value"/></xsl:variable>
    <xsl:variable name="type"><xsl:value-of select="document('config.xml',.)//option[@name=$confexpr]/attribute::type"/></xsl:variable>
    <xsl:choose>
     <xsl:when test="$type='boolean'">
      <xsl:choose>
       <xsl:when test="$value='true'"><xsl:text>0</xsl:text></xsl:when>
       <xsl:when test="$value='false'"><xsl:text>1</xsl:text></xsl:when>
       <!-- boolean but no value is false -->
       <xsl:when test="$value=''"><xsl:text>1</xsl:text></xsl:when>
       <xsl:otherwise>
       <xsl:message terminate="yes">Error:<xsl:value-of select="$confexpr"/> has no valid value '<xsl:value-of select="$value"/>'.</xsl:message>
      </xsl:otherwise>
      
      </xsl:choose>
     </xsl:when>
     <!-- if it doesn't exist, it is false -->
     <xsl:when test="$type=''"><xsl:text>1</xsl:text></xsl:when>
     <xsl:otherwise>
      <xsl:message terminate="yes">Error:<xsl:value-of select="$confexpr"/> is not a boolean value ('<xsl:value-of select="$type"/>').</xsl:message>
     </xsl:otherwise>
    </xsl:choose>
    <!-- debug - ->
     <xsl:message>
     <xsl:value-of select="$confexpr"/> = <xsl:value-of select="$value"/>
     </xsl:message>
    <!- - -->
   </xsl:when>
   <!-- if no expression is there we return true -->
   <xsl:otherwise>0</xsl:otherwise>
  </xsl:choose>
</xsl:template>


</xsl:stylesheet>
