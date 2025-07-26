package org.tsicoop.dpdpcms.framework;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.sql.*;
import java.text.SimpleDateFormat;


@SuppressWarnings("unchecked")
public abstract class DB {

    Connection con = null;

    public DB(){}

    public DB(Connection con){
        this.con = con;
    }

    public void close(Connection con) {
        try {
            if (con != null) {
                con.close();
            }
        } catch (Exception e) {
        }
    }

    public void close(ResultSet rs) {
        try {
            if (rs != null) {
                rs.close();
            }
        } catch (Exception e) {
        }
    }

    public void close(PreparedStatement pStmt) {
        try {
            if (pStmt != null) {
                pStmt.close();
            }
        } catch (Exception e) {
        }
    }

    public void cleanup(ResultSet rs, PreparedStatement pStmt, Connection con) {
        close(rs);
        close(pStmt);
        close(con);
    }

    public static void close(Statement stmt) {
        try {
            if (stmt != null) {
                stmt.close();
            }
        } catch (Exception e) {
        }
    }

    public void rollback(Connection con) {
        try {
            if (con != null) {
                con.rollback();
            }
        } catch (Exception e) {
        }
    }

    public JSONArray getResults(ResultSet rs) {
        JSONArray jsonResultArr = new JSONArray();
        try {
            if (rs != null) {
                while (rs.next()) {
                    JSONObject json = getJSON(rs);
                    jsonResultArr.add(json);
                }
            }
        } catch (SQLException e) {
        }
        return jsonResultArr;
    }

    public JSONObject getResult(ResultSet rs) {
        JSONObject jsonResult = new JSONObject();
        try {
            if (rs != null && rs.next()) {
                jsonResult = getJSON(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return jsonResult;
    }

    public JSONObject getResultsWithHeader(ResultSet rs) {
        JSONObject jsonResult = new JSONObject();
        try {
            if (rs != null) {
                ResultSetMetaData rsmd = rs.getMetaData();
                JSONArray header = new JSONArray();
                for (int i = 1, colCount = rsmd.getColumnCount(); i <= colCount; i++) {
                    header.add(rsmd.getColumnLabel(i));
                }
                JSONArray jsonResultArr = new JSONArray();
                while (rs.next()) {
                    JSONObject json = getJSON(rs);
                    jsonResultArr.add(json);
                }
                jsonResult.put("header", header);
                jsonResult.put("data", jsonResultArr);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return jsonResult;
    }

//	public static boolean writeToExcel(ResultSet rs, OutputStream os) {
//		try {
//			WritableWorkbook wworkbook = Workbook.createWorkbook(os);
//			WritableSheet wsheet = wworkbook.createSheet("Sheet 1", 0);
//
//		    // Create cell font and format
//		    WritableFont cellFontTitle = new WritableFont(WritableFont.ARIAL, 14);
//		    cellFontTitle.setBoldStyle(WritableFont.BOLD);
//		    WritableCellFormat cellFormatTitle = new WritableCellFormat(cellFontTitle);
//		    cellFormatTitle.setBorder(Border.ALL, BorderLineStyle.THIN);
//		    cellFormatTitle.setAlignment(Alignment.CENTRE);
//		    cellFormatTitle.setWrap(false);
//
//			// Create cell font and format
//		    WritableFont cellFontHeader = new WritableFont(WritableFont.ARIAL, 10);
//		    cellFontHeader.setBoldStyle(WritableFont.BOLD);
//		    WritableCellFormat cellFormatHeader = new WritableCellFormat(cellFontHeader);
//		    cellFormatHeader.setBorder(Border.ALL, BorderLineStyle.THIN);
//		    cellFormatHeader.setAlignment(Alignment.CENTRE);
//		    cellFormatHeader.setWrap(false);
//
//
//		    // Create cell font and format
//		    WritableFont cellFontNormal = new WritableFont(WritableFont.ARIAL, 10);
//		    WritableCellFormat cellFormatNormal = new WritableCellFormat(cellFontNormal);
//		    cellFormatNormal.setBorder(Border.ALL, BorderLineStyle.THIN);
//		    cellFormatNormal.setWrap(false);
//
//		    int row = 1;
//
//			if(rs != null) {
//				ResultSetMetaData rsmd = rs.getMetaData();
//				for(int i=1, colCount = rsmd.getColumnCount();i<=colCount;i++){
//					wsheet.addCell(new Label(i-1, row, rsmd.getColumnLabel(i), cellFormatHeader));
//				}
//				SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");
//				SimpleDateFormat sdfTimeStamp = new SimpleDateFormat("dd-MM-yyyy hh:mm:ss a");
//				while(rs.next()){
//					row++;
//					for(int i=1, colCount = rsmd.getColumnCount();i<=colCount;i++) {
//
//						switch(rsmd.getColumnType(i)){
//							case Types.VARCHAR :
//							case Types.CHAR :{
//								wsheet.addCell(new Label(i-1, row, rs.getString(i), cellFormatNormal));
//								break;
//							}
//							case Types.TIMESTAMP:{
//								Timestamp timeStamp = rs.getTimestamp(i);
//								String sTimeStamp = "";
//								if(timeStamp != null){
//									sTimeStamp = sdfTimeStamp.format(new Date(timeStamp.getTime()));
//								}
//								wsheet.addCell(new Label(i-1, row, sTimeStamp, cellFormatNormal));
//								break;
//							}
//							case Types.DATE : {
//								Date date = rs.getDate(i);
//								String sDate = "";
//								if(date != null) {
//									sdf.format(date);
//								}
//								wsheet.addCell(new Label(i-1, row, sDate, cellFormatNormal));
//								break;
//							}
//							case Types.BIGINT :
//							case Types.NUMERIC :{
//								wsheet.addCell(new Number(i-1, row, rs.getLong(i), cellFormatNormal));
//								break;
//							}
//							case Types.INTEGER :{
//								wsheet.addCell(new Number(i-1, row, rs.getInt(i), cellFormatNormal));
//								break;
//							}
//
//							case Types.FLOAT :{
//								wsheet.addCell(new Number(i-1, row, rs.getFloat(i), cellFormatNormal));
//								break;
//							}
//							case Types.DECIMAL :{
//								wsheet.addCell(new Number(i-1, row, rs.getDouble(i), cellFormatNormal));
//								break;
//							}
//							case Types.DOUBLE :{
//								wsheet.addCell(new Number(i-1, row, rs.getDouble(i), cellFormatNormal));
//								break;
//							}
//							default : {
//								wsheet.addCell(new Label(i-1, row, rs.getString(i), cellFormatNormal));
//							}
//
//						}
//					}
//				}
//			}
//			wworkbook.write();
//		    wworkbook.close();
//		} catch (SQLException e) {
//			e.printStackTrace();
//			return false;
//		} catch (IOException e) {
//			e.printStackTrace();
//			return false;
//		} catch (WriteException e) {
//			e.printStackTrace();
//		}
//		return true;
//	}

    private static JSONObject getJSON(ResultSet rs) throws SQLException {
        ResultSetMetaData rsmd = rs.getMetaData();
        JSONObject json = new JSONObject();
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");
        SimpleDateFormat sdfTimeStamp = new SimpleDateFormat("dd-MM-yyyy hh:mm:ss a");
        for (int index = 1, colCount = rsmd.getColumnCount(); index <= colCount; index++) {
            Object value = null;
            switch (rsmd.getColumnType(index)) {
                case Types.VARCHAR:
                case Types.CHAR: {
                    value = rs.getString(index);
                    if (value == null) value = "";
                }
                break;

                case Types.TIMESTAMP: {
                    Timestamp timeStamp = rs.getTimestamp(index);
                    String sTimeStamp = "";
                    if (timeStamp != null) {
                        sTimeStamp = sdfTimeStamp.format(new Date(timeStamp.getTime()));
                    }
                    value = sTimeStamp;
                }
                break;

                case Types.DATE: {
                    Date date = rs.getDate(index);
                    if (date != null) {
                        value = sdf.format(date);
                    }
                }
                break;

                case Types.BIGINT:
                case Types.NUMERIC: {
                    value = rs.getLong(index);
                }
                break;

                case Types.INTEGER: {
                    value = rs.getInt(index);
                }
                break;

                case Types.FLOAT: {
                    value = rs.getFloat(index);
                }
                break;

                case Types.DECIMAL: {
                    value = rs.getDouble(index);
                }
                break;

                case Types.DOUBLE: {
                    value = rs.getDouble(index);
                }
                break;

                default: {
                    value = rs.getString(index);
                    if (value == null) value = "";
                }
            }
            json.put(rsmd.getColumnLabel(index), value);
        }
        return json;
    }
}