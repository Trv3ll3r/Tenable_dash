# Ticket Tracking Feature Implementation Guide

## Overview
This feature adds the ability to track which vulnerabilities have had tickets created, with automatic clearing when Tenable marks findings as FIXED.

## Files Created/Modified

### 1. Templates
- **grouped_findings.html** - Updated with ticket checkbox column and filtering

### 2. Backend Routes (main.py)
- `grouped_findings()` - Updated with ticket filtering logic
- `toggle_ticket()` - NEW: API endpoint to toggle ticket status
- `auto_clear_fixed_tickets()` - NEW: API endpoint to clear fixed tickets

### 3. Database
- **Migration script**: `add_ticket_tracking_migration.py`
- **Model update**: Add `ticket_created` field to `VulnerabilityFinding`

## Implementation Steps

### Step 1: Update the Database Model

Add this field to your `VulnerabilityFinding` model in `models.py`:

```python
ticket_created = db.Column(db.Boolean, default=False, nullable=True)
```

### Step 2: Run the Migration

```bash
python add_ticket_tracking_migration.py
```

This will:
- Add the `ticket_created` column to your database
- Initialize all existing records to `False`
- Work with SQLite, PostgreSQL, and MySQL

**Alternative: Using Alembic**
```bash
alembic revision --autogenerate -m "Add ticket_created field"
alembic upgrade head
```

### Step 3: Update Your Routes

Replace the `grouped_findings()` function in `main.py` with the updated version that includes:
- `selected_ticket_status` parameter
- Ticket filtering logic
- `ticket_stats` calculation
- `has_ticket` field in grouped findings

Add the two new routes:
- `/toggle_ticket/<int:plugin_id>` (POST)
- `/auto_clear_fixed_tickets` (POST)

### Step 4: Replace the Template

Replace `templates/grouped_findings.html` with the new version that includes:
- Ticket status dropdown filter
- Checkbox column in the table
- JavaScript for handling checkbox changes
- "Clear Fixed Tickets" button
- Ticket statistics display

### Step 5: Restart Your Application

```bash
# Stop your application
# Then restart it
python run.py
```

## Features

### 1. Ticket Checkbox
- Check the box when you create a ticket for a vulnerability
- Unchecking removes the ticket flag
- Updates all findings for that plugin_id

### 2. Filtering
Three filter options:
- **All** - Show all vulnerabilities
- **No Ticket** - Show only vulnerabilities without tickets
- **Has Ticket** - Show only vulnerabilities with tickets created

### 3. Auto-Clear Fixed
- Button to automatically uncheck all tickets for FIXED findings
- Useful for keeping your ticket tracking clean
- Confirms before execution

### 4. Statistics
Dashboard shows:
- Number of vulnerabilities with tickets
- Number of vulnerabilities needing tickets
- Auto-clear reminder

## Usage Workflow

1. **View grouped findings** without tickets:
   - Set filter to "No Ticket"
   - See all vulnerabilities needing tickets

2. **Create a ticket** in your ticketing system:
   - Export the vulnerability as TXT
   - Create ticket in Jira/ServiceNow/etc.
   - Check the box in the dashboard

3. **Track progress**:
   - Filter by "Has Ticket" to see tracked items
   - Monitor until Tenable marks as FIXED

4. **Clean up**:
   - When Tenable marks findings as FIXED
   - Click "Clear Fixed Tickets" to auto-uncheck
   - Or let natural remediation flow handle it

## API Endpoints

### Toggle Ticket Status
```
POST /toggle_ticket/<plugin_id>
Content-Type: application/json

{
    "ticket_created": true
}

Response:
{
    "success": true,
    "plugin_id": 12345,
    "ticket_created": true,
    "updated_count": 5
}
```

### Auto-Clear Fixed Tickets
```
POST /auto_clear_fixed_tickets
Content-Type: application/json

Response:
{
    "success": true,
    "cleared_count": 12
}
```

## Database Schema

### vulnerability_findings table
```sql
ALTER TABLE vulnerability_findings 
ADD COLUMN ticket_created BOOLEAN DEFAULT FALSE;
```

## Troubleshooting

### Checkbox not working
- Check browser console for JavaScript errors
- Verify `/toggle_ticket/<id>` route is accessible
- Check database permissions

### Migration fails
- Ensure database is accessible
- Check if column already exists
- Verify database URL in environment

### Statistics not updating
- Refresh the page after checking boxes
- Check server logs for errors
- Verify query filtering logic

## Benefits

1. **Workflow Management**: Track which vulnerabilities have tickets
2. **Prioritization**: Focus on items without tickets first
3. **Automation**: Auto-clear when Tenable marks as fixed
4. **Team Coordination**: Everyone sees ticket status
5. **Reporting**: Filter and export based on ticket status

## Future Enhancements

Possible additions:
- Ticket ID field to link directly to ticketing system
- Assignee tracking
- Due date tracking
- Bulk ticket operations
- Integration with Jira/ServiceNow APIs
- Ticket creation date timestamp
- Comments/notes field

## Support

If you encounter issues:
1. Check server logs for error messages
2. Verify database migration completed
3. Test API endpoints directly
4. Review JavaScript console for frontend errors